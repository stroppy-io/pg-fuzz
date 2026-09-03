package coverage

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// NOTHING IN THE PORT MEASURED COVERAGE.
//
// FindProfiles reads a directory layout only the deleted shell could create,
// so `pgfuzz coverage` was a view over leftovers: once those were pruned or a
// new build landed it would have returned nothing, forever, while still
// exiting 0.
//
// This is the producer. It replays a target's corpus under the instrumented
// build and records what came back.

// MeasureRequest is one target's coverage replay.
type MeasureRequest struct {
	OSSFuzz string // the clone helper.py lives in
	Project string // pgfuzz-<workspace>
	Target  string
	Corpus  string // the corpus directory to replay
	Out     string // the build, where report_target lands
	// Sanitizer of the build being measured, so a non-coverage build is
	// refused rather than measured to zero.
	Sanitizer string
	// MinFreeGB refuses to start without headroom; StopFreeGB kills the run
	// if the disk falls below it while replaying.
	MinFreeGB, StopFreeGB float64
	Stream                io.Writer
}

// Summary of one target, as base-runner writes it.
type TargetSummary struct {
	Target                            string    `json:"target"`
	When                              time.Time `json:"when"`
	Lines, Functions, Regions, Branch Counts    `json:"-"`
}

// Counts is llvm-cov's covered/count pair.
type Counts struct {
	Count   int     `json:"count"`
	Covered int     `json:"covered"`
	Percent float64 `json:"percent"`
}

// Measure replays a corpus under the instrumented build and returns what the
// run itself produced.
//
// THE FRESHNESS STAMP IS THE POINT. summary.json is left behind by the
// previous run, so a run that dies or half-completes leaves the older file in
// place -- and reading it back records a number no run produced. That is how
// a round once recorded coverage DOWN 6.8% from a binary that had not changed:
// llvm-cov reports only the files present in the profile, so an incomplete
// profile loses denominator as well as covered lines. A drop from an unchanged
// build is a broken measurement, not a regression, and a coverage point that
// silently substitutes the previous run's number is worse than a missing one
// because it looks like data.
func Measure(ctx context.Context, r MeasureRequest) (TargetSummary, error) {
	var out TargetSummary
	if r.Sanitizer != "coverage" {
		return out, fmt.Errorf(
			"this workspace is a %s build; coverage needs a build made with "+
				"-sanitizer coverage, and measuring an instrumented-for-crashes "+
				"build reports numbers that mean nothing", r.Sanitizer)
	}
	if r.MinFreeGB > 0 {
		if free, err := freeGB(r.Out); err == nil && free < r.MinFreeGB {
			return out, fmt.Errorf(
				"%.0f GB free where the report is written, need %.0f -- a coverage "+
					"replay writes a profile per input", free, r.MinFreeGB)
		}
	}

	summary := filepath.Join(r.Out, "report_target", r.Target, "linux", "summary.json")
	started := time.Now()

	// A DISK GUARD FOR THE DURATION. A replay writes a profile per input and
	// can fill a disk mid-run; ENOSPC then surfaces as an unrelated failure
	// far from the cause, and can truncate a corpus.
	stopGuard := make(chan struct{})
	if r.StopFreeGB > 0 {
		go func() {
			t := time.NewTicker(30 * time.Second)
			defer t.Stop()
			for {
				select {
				case <-stopGuard:
					return
				case <-t.C:
					if free, err := freeGB(r.Out); err == nil && free < r.StopFreeGB {
						fmt.Fprintf(os.Stderr,
							"pgfuzz: only %.0f GB free -- stopping the coverage run\n", free)
						killByAncestor("gcr.io/oss-fuzz/" + r.Project)
						return
					}
				}
			}
		}()
	}

	cmd := exec.CommandContext(ctx, "python3", "infra/helper.py", "coverage",
		"--no-serve", "--port", "", "--corpus-dir", r.Corpus,
		r.Project, "--fuzz-target", r.Target)
	cmd.Dir = r.OSSFuzz
	cmd.Stdout, cmd.Stderr = r.Stream, r.Stream
	runErr := cmd.Run()
	close(stopGuard)

	fi, err := os.Stat(summary)
	if err != nil {
		return out, fmt.Errorf("no summary for %s: %v (run: %v)", r.Target, err, runErr)
	}
	// WRITTEN BY THIS RUN, or it is the previous one's.
	if fi.ModTime().Before(started) {
		return out, fmt.Errorf(
			"%s: summary.json predates this run (%s) -- the replay did not complete,"+
				" and its contents are the PREVIOUS run's numbers. Not recorded.",
			r.Target, fi.ModTime().UTC().Format(time.RFC3339))
	}

	b, err := os.ReadFile(summary)
	if err != nil {
		return out, err
	}
	var doc struct {
		Data []struct {
			Totals struct {
				Lines     Counts `json:"lines"`
				Functions Counts `json:"functions"`
				Regions   Counts `json:"regions"`
				Branches  Counts `json:"branches"`
			} `json:"totals"`
		} `json:"data"`
	}
	if err := json.Unmarshal(b, &doc); err != nil || len(doc.Data) == 0 {
		return out, fmt.Errorf("%s: summary.json is not a coverage report", r.Target)
	}
	t := doc.Data[0].Totals
	out = TargetSummary{Target: r.Target, When: time.Now().UTC()}
	out.Lines, out.Functions, out.Regions, out.Branch =
		t.Lines, t.Functions, t.Regions, t.Branches
	return out, nil
}

// RecordTarget appends one measurement to the coverage series.
//
// THE TREND IS THE ANSWER, not the number. summary.json is overwritten by the
// next run, so a file that is replaced each time carries none -- and "has
// coverage stopped growing" is the question worth asking.
func RecordTarget(path string, ws string, s TargetSummary) error {
	row := struct {
		When      string `json:"when"`
		WS        string `json:"ws"`
		Target    string `json:"target"`
		Lines     Counts `json:"lines"`
		Functions Counts `json:"functions"`
		Regions   Counts `json:"regions"`
		Branches  Counts `json:"branches"`
	}{
		When: s.When.Format(time.RFC3339), WS: ws, Target: s.Target,
		Lines: s.Lines, Functions: s.Functions, Regions: s.Regions, Branches: s.Branch,
	}
	b, err := json.Marshal(row)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(append(b, '\n'))
	return err
}

// freeGB is the space left where this path lives.
func freeGB(path string) (float64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, err
	}
	return float64(st.Bavail) * float64(st.Bsize) / (1 << 30), nil
}

// killByAncestor stops the containers of one project image.
//
// Two commands, not one shell string: `docker kill $(docker ps -q ...)` only
// works when a shell expands it, and passing it to exec runs a container named
// "$(docker".
func killByAncestor(image string) {
	out, err := exec.Command("docker", "ps", "-q", "--filter", "ancestor="+image).Output()
	if err != nil {
		return
	}
	for _, id := range strings.Fields(string(out)) {
		exec.Command("docker", "kill", id).Run()
	}
}

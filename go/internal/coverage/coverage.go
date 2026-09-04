// Package coverage measures what the campaign actually reached.
//
// THE TWO MISTAKES THIS CODE EXISTS TO NOT REPEAT
// ===============================================
//
// PLUGINS ARE INVISIBLE TO coverage_helper. It builds its -object list by
// walking DT_NEEDED, and PostgreSQL loads extensions with dlopen -- so no
// plugin ever appears, and a report that looks complete covers only core.
// Every .so under tmp_install is added explicitly. Passing one -object is not
// enough either: that reported zero plugin components while looking healthy.
//
// A UNION IS NOT THE LARGEST MEMBER. Merging one target's profile and calling
// it the campaign's coverage is a mistake that reads as success -- it was
// caught only because the union came out SMALLER than one of its parts. The
// merge takes every per-target profile and llvm-cov counts each line once.
package coverage

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Summary is what a union produced.
type Summary struct {
	When      time.Time `json:"when"`
	Targets   int       `json:"targets"`
	Lines     Counted   `json:"lines"`
	Functions Counted   `json:"functions"`
	Regions   Counted   `json:"regions"`
	Branches  Counted   `json:"branches"`
	Files     int       `json:"files"`
	FilesSeen int       `json:"files_entered"`

	// Anchor is the binary the objects were taken from.
	//
	// THE SCOPE OF THE MEASUREMENT, and it was not recorded anywhere. The
	// union merges every target's profile, but llvm-cov needs objects, and
	// passing all 23 binaries would count the statically-linked backend once
	// per binary in the denominator -- so one anchor is chosen and its
	// DT_NEEDED libraries and the installed .so files go with it.
	//
	// The consequence is real and worth stating rather than hiding: a
	// function linked ONLY into some other target -- the libpq-only ones,
	// conninfo_fuzzer among them -- contributes profile counters but no
	// object, so it drops out of the numerator AND the denominator. The
	// percentage is honest for what it covers; this field says what that is.
	Anchor string `json:"anchor,omitempty"`
}

// Counted is covered-of-total.
type Counted struct {
	Covered int `json:"covered"`
	Count   int `json:"count"`
}

// Pct is the percentage, and zero when nothing was counted -- a report that
// prints NaN teaches people to ignore the number.
func (c Counted) Pct() float64 {
	if c.Count == 0 {
		return 0
	}
	return 100 * float64(c.Covered) / float64(c.Count)
}

// UnionRequest merges per-target profiles into one measurement.
type UnionRequest struct {
	Out      string   // the coverage build, bind-mounted read-only
	Profiles []string // per-target .profdata files
	Stage    string   // a writable directory for the merge
	Image    string
	Stream   io.Writer
	Timeout  time.Duration
}

// The container runs THIS BINARY. See internal/incontainer.

// Union merges every profile and reports the combined coverage.
func Union(ctx context.Context, r UnionRequest) (Summary, error) {
	if len(r.Profiles) == 0 {
		return Summary{}, fmt.Errorf("no profiles to merge")
	}
	if r.Image == "" {
		r.Image = "gcr.io/oss-fuzz-base/base-runner:ubuntu-24-04"
	}
	if r.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, r.Timeout)
		defer cancel()
	}
	// WIPED, not just created. The container globs /stage/*.profdata, and the
	// previous run left its own union.profdata there -- so without this every
	// union re-merges the last one plus any target profile that is no longer
	// newest. The number can then only ever go up, which makes a coverage
	// regression unreportable, and "newest per target" silently becomes
	// "everything this workspace ever measured".
	if err := os.RemoveAll(r.Stage); err != nil {
		return Summary{}, err
	}
	if err := os.MkdirAll(r.Stage, 0o755); err != nil {
		return Summary{}, err
	}
	for _, p := range r.Profiles {
		b, err := os.ReadFile(p)
		if err != nil {
			return Summary{}, fmt.Errorf("reading %s: %w", p, err)
		}
		if err := os.WriteFile(filepath.Join(r.Stage, filepath.Base(p)), b, 0o644); err != nil {
			return Summary{}, err
		}
	}

	obj, err := largestTarget(r.Out)
	if err != nil {
		return Summary{}, err
	}
	self, err := os.Executable()
	if err != nil {
		return Summary{}, err
	}
	if real, err := filepath.EvalSymlinks(self); err == nil {
		self = real
	}

	cmd := exec.CommandContext(ctx, "docker", "run", "--rm", "--platform", "linux/amd64",
		"-v", r.Out+":/out:ro", "-v", r.Stage+":/stage",
		"-e", fmt.Sprintf("PGFUZZ_UID=%d:%d", os.Getuid(), os.Getgid()),
		"-v", self+":/pgfuzz:ro",
		"--entrypoint", "/pgfuzz", r.Image, "_covunion", obj)
	var buf bytes.Buffer
	var sink io.Writer = &buf
	if r.Stream != nil {
		sink = io.MultiWriter(&buf, r.Stream)
	}
	cmd.Stdout, cmd.Stderr = sink, sink
	if err := cmd.Run(); err != nil {
		return Summary{}, fmt.Errorf("llvm-cov: %w\n%s", err, tailOf(buf.String(), 15))
	}
	sum, err := parseSummary(filepath.Join(r.Stage, "union-summary.json"), len(r.Profiles))
	// Which binary's objects the percentages are against. Without it a reader
	// cannot tell what the denominator covers.
	sum.Anchor = filepath.Base(obj)
	return sum, err
}

// largestTarget picks the binary to report against.
//
// The largest, because llvm-cov needs one object that carries the core
// instrumentation and the biggest target is the one most likely to have linked
// all of it. The plugins are added separately; this is only the anchor.
func largestTarget(out string) (string, error) {
	ents, err := os.ReadDir(out)
	if err != nil {
		return "", err
	}
	type cand struct {
		name string
		size int64
	}
	var best cand
	for _, e := range ents {
		n := e.Name()
		// The binaries have no extension; .dict, .options and the seed-corpus
		// zips sit beside them and are not objects.
		if filepath.Ext(n) != "" || !strings.HasSuffix(n, "_fuzzer") {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		if fi.Size() > best.size {
			best = cand{n, fi.Size()}
		}
	}
	if best.name == "" {
		return "", fmt.Errorf("no fuzz target binary in %s", out)
	}
	return best.name, nil
}

type llvmExport struct {
	Data []struct {
		Totals map[string]struct {
			Covered int `json:"covered"`
			Count   int `json:"count"`
		} `json:"totals"`
		Files []struct {
			Summary struct {
				Lines struct {
					Covered int `json:"covered"`
					Count   int `json:"count"`
				} `json:"lines"`
			} `json:"summary"`
		} `json:"files"`
	} `json:"data"`
}

func parseSummary(path string, targets int) (Summary, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Summary{}, fmt.Errorf("no union summary: %w", err)
	}
	var e llvmExport
	if err := json.Unmarshal(b, &e); err != nil {
		return Summary{}, fmt.Errorf("union summary: %w", err)
	}
	if len(e.Data) == 0 {
		return Summary{}, fmt.Errorf("union summary has no data")
	}
	d := e.Data[0]
	get := func(k string) Counted {
		t := d.Totals[k]
		return Counted{Covered: t.Covered, Count: t.Count}
	}
	s := Summary{
		When: time.Now().UTC(), Targets: targets,
		Lines: get("lines"), Functions: get("functions"),
		Regions: get("regions"), Branches: get("branches"),
		Files: len(d.Files),
	}
	for _, f := range d.Files {
		if f.Summary.Lines.Covered > 0 {
			s.FilesSeen++
		}
	}
	return s, nil
}

// FindProfiles collects per-target profiles, newest per target.
//
// Newest per TARGET, not newest overall: a pass that re-measured six targets
// must not throw away the seventeen from the pass before it, and taking a
// single directory reported one target's coverage as the whole campaign's.
func FindProfiles(root, buildOut string) ([]string, error) {
	// TWO LAYOUTS, and only one of them is still written.
	//
	// base-runner writes $OUT/dumps/<target>.profdata, which is where every
	// profile this tool produces lands. The glob here looked only under
	// .cov-parallel-*/<t>/upper/dumps/ -- a layout the deleted shell created
	// and nothing in the port does. So -measure wrote profiles that -union
	// could not see: a union merged shell-era leftovers, or reported "no
	// per-target profiles on disk" for a workspace that had just measured
	// every target.
	//
	// The old layout is still read because sixteen of those directories exist
	// on this host and their measurements are real; it is a fallback, not the
	// source.
	var hits []string
	if buildOut != "" {
		m, err := filepath.Glob(filepath.Join(buildOut, "dumps", "*.profdata"))
		if err != nil {
			return nil, err
		}
		hits = append(hits, m...)
	}
	legacy, err := filepath.Glob(filepath.Join(root, ".cov-parallel-*", "*", "upper", "dumps", "*.profdata"))
	if err != nil {
		return nil, err
	}
	hits = append(hits, legacy...)
	best := map[string]string{}
	bestAt := map[string]time.Time{}
	for _, p := range hits {
		name := filepath.Base(p)
		target := name[:len(name)-len(".profdata")]
		if target == "merged" {
			continue
		}
		fi, err := os.Stat(p)
		if err != nil {
			continue
		}
		if at, ok := bestAt[target]; !ok || fi.ModTime().After(at) {
			best[target], bestAt[target] = p, fi.ModTime()
		}
	}
	out := make([]string, 0, len(best))
	for _, p := range best {
		out = append(out, p)
	}
	sort.Strings(out)
	return out, nil
}

func tailOf(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

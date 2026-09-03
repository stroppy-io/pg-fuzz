package repro

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// SweepResult is one artifact's verdict.
type SweepResult struct {
	Target    string
	Artifact  string
	Verdict   Verdict
	Signature string // normalised, so two runs of one defect agree
}

// NormaliseSignature makes a crash line usable as a dedup key.
//
// THE RAW LINE IS NOT A KEY. It carries the pid (`==21==`) and the build path
// (`/src/postgres/bld/../`), both of which differ between two runs of the same
// defect -- so grouping on it splits one finding into as many rows as it was
// reproduced. The old sweep stripped exactly these before counting, and the
// census does the same for log-derived signatures; the reproduce path kept the
// whole line and had no consumer to notice.
func NormaliseSignature(s string) string {
	s = strings.TrimSpace(s)
	s = rePID.ReplaceAllString(s, "==")
	s = strings.ReplaceAll(s, "/src/postgres/bld/../", "")
	s = strings.ReplaceAll(s, "/src/postgres/", "")
	if len(s) > 160 {
		s = s[:160]
	}
	return s
}

var rePID = regexp.MustCompile(`==\d+==`)

// Sweep reproduces every artifact of a workspace and groups them by signature.
//
// WHAT IT REFUSES TO DO IS THE POINT. Two guards existed in the shell and both
// were written after being paid for:
//
//   - No built targets: every reproduction fails identically against an empty
//     directory, and the report read "131 artifacts, all did not reproduce".
//   - A build whose sanitizer cannot report: a coverage build does not fail,
//     it SUCCEEDS and reports nothing, which is indistinguishable from "no
//     crash". Sweeping artifacts against one yields a clean sheet that means
//     nothing at all.
func Sweep(ctx context.Context, wsDir, outDir, image, sanitizer string,
	runs int, out io.Writer) ([]SweepResult, error) {

	if sanitizer == "coverage" || sanitizer == "none" {
		return nil, fmt.Errorf(
			"this workspace is a %s build: it cannot report a crash, so every "+
				"artifact would come back clean and mean nothing. Sweep an "+
				"address or undefined build instead", sanitizer)
	}
	targets, err := builtTargets(outDir)
	if err != nil || len(targets) == 0 {
		return nil, fmt.Errorf(
			"no built targets in %s -- every reproduction would fail identically "+
				"and read as 'did not reproduce'", outDir)
	}
	built := map[string]bool{}
	for _, t := range targets {
		built[t] = true
	}

	dirs, _ := filepath.Glob(filepath.Join(wsDir, "artifacts", "*_fuzzer"))
	sort.Strings(dirs)

	var results []SweepResult
	for _, d := range dirs {
		target := filepath.Base(d)
		if !built[target] {
			continue
		}
		arts, _ := os.ReadDir(d)
		for _, a := range arts {
			if a.IsDir() || !IsArtifact(a.Name()) {
				continue
			}
			path := filepath.Join(d, a.Name())
			res, _ := Run(ctx, Request{
				Image: image, Out: outDir, Target: target,
				Input: path, Runs: runs,
			})
			sr := SweepResult{
				Target: target, Artifact: a.Name(), Verdict: res.Verdict,
				Signature: NormaliseSignature(res.Signature),
			}
			if sr.Signature == "" {
				// An explicit bucket, never an empty string folded in with the
				// others: "did not reproduce" is a finding about the artifact.
				sr.Signature = fmt.Sprintf("NO-SIGNATURE (%s)", res.Verdict)
			}
			results = append(results, sr)
			if out != nil {
				fmt.Fprintf(out, "  %-24s %-10s %s\n", target, res.Verdict, a.Name())
			}
		}
	}
	return results, nil
}

// GroupBySignature counts how many artifacts share each signature.
func GroupBySignature(rs []SweepResult) map[string][]SweepResult {
	out := map[string][]SweepResult{}
	for _, r := range rs {
		out[r.Signature] = append(out[r.Signature], r)
	}
	return out
}

// IsArtifact reports whether a filename is a libFuzzer reproducer.
func IsArtifact(name string) bool {
	for _, p := range []string{"crash-", "leak-", "timeout-", "oom-"} {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

func builtTargets(out string) ([]string, error) {
	ents, err := os.ReadDir(out)
	if err != nil {
		return nil, err
	}
	var ts []string
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), "_fuzzer") {
			continue
		}
		if fi, err := e.Info(); err == nil && fi.Mode()&0o111 != 0 {
			ts = append(ts, e.Name())
		}
	}
	sort.Strings(ts)
	return ts, nil
}

package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeUnion(t *testing.T, dir string, recs ...string) string {
	t.Helper()
	run := filepath.Join(dir, "series")
	if err := os.MkdirAll(run, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(run, "coverage-union.jsonl"),
		[]byte(strings.Join(recs, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// A FAILED MEASUREMENT MUST NOT LEAVE THE PREVIOUS ONE STANDING.
//
// coverageOf took the last record with a non-zero line count, so a run whose
// coverage measurement produced nothing showed the earlier measurement's
// percentage in its column, with nothing to say it was older. The column then
// reported coverage for a run that had measured none.
func TestCoverageMarksAStaleFallback(t *testing.T) {
	dir := writeUnion(t, t.TempDir(),
		`{"lines":{"count":1000,"covered":250},"targets":23}`,
		`{"lines":{"count":0,"covered":0},"targets":0}`)

	cov, targets, stale, ok := coverageOf(dir)
	if !ok {
		t.Fatal("no coverage read at all")
	}
	if cov != "25.00%" {
		t.Errorf("cov = %q, want the last measurement that worked", cov)
	}
	if !stale {
		t.Error("an older measurement was presented as this run's own")
	}
	if targets != 23 {
		t.Errorf("targets = %d, want the scope of the measurement shown", targets)
	}
}

// The ordinary case stays unmarked, and carries its scope: a union over 23
// targets and one over 46 are not the same measurement and must not print
// identically with nothing to tell them apart.
func TestCoverageCarriesItsScope(t *testing.T) {
	dir := writeUnion(t, t.TempDir(),
		`{"lines":{"count":1000,"covered":100},"targets":46}`,
		`{"lines":{"count":1000,"covered":250},"targets":23}`)

	cov, targets, stale, ok := coverageOf(dir)
	if !ok || cov != "25.00%" {
		t.Fatalf("cov = %q ok=%v, want the newest measurement", cov, ok)
	}
	if stale {
		t.Error("a good newest measurement was marked stale")
	}
	if targets != 23 {
		t.Errorf("targets = %d, want 23 from the newest record", targets)
	}
}

// Nothing measured is still nothing, not a zero percent.
func TestCoverageAbsentIsAbsent(t *testing.T) {
	dir := writeUnion(t, t.TempDir(), `{"lines":{"count":0,"covered":0}}`)
	if _, _, _, ok := coverageOf(dir); ok {
		t.Error("a file with no usable record reported coverage anyway")
	}
	if _, _, _, ok := coverageOf(t.TempDir()); ok {
		t.Error("a run with no coverage file reported coverage")
	}
}

package tui

import (
	"os"
	"path/filepath"
	"testing"
)

// Row.CovPct was declared, read by the renderer, and assigned by nobody, so
// the dashboard's cov column read "-" forever. The old dashboard also
// remapped the workspace: coverage is measured in its own instrumented build,
// so pg17-add's coverage lives under pg17-cov.
func TestCoveragePctReadsTheCovWorkspace(t *testing.T) {
	p := filepath.Join(t.TempDir(), "coverage-series.jsonl")
	body := `{"ws":"pg17-cov","lines":{"count":1000,"covered":250}}
{"ws":"other-cov","lines":{"count":1000,"covered":900}}
{"ws":"pg17-cov","lines":{"count":1000,"covered":314}}
`
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	// A fuzzing workspace is answered by its -cov twin, newest row wins.
	if got := CoveragePct(p, "pg17-add"); got != 31.4 {
		t.Errorf("pg17-add coverage = %.1f, want 31.4 from pg17-cov", got)
	}
	if got := CoveragePct(p, "pg17-und"); got != 31.4 {
		t.Errorf("pg17-und coverage = %.1f, want 31.4 from pg17-cov", got)
	}
	// Not recorded is zero, which the grid renders as "-" rather than as a
	// measured zero. Those are different states.
	if got := CoveragePct(p, "nothing-add"); got != 0 {
		t.Errorf("an unmeasured workspace reported %.1f", got)
	}
}

func TestCovWorkspaceMapping(t *testing.T) {
	for in, want := range map[string]string{
		"pg17-add":  "pg17-cov",
		"pg17-und":  "pg17-cov",
		"pg17-cov":  "pg17-cov",
		"gt-master": "gt-master",
	} {
		if got := CovWorkspace(in); got != want {
			t.Errorf("CovWorkspace(%q) = %q, want %q", in, got, want)
		}
	}
}

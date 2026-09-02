package findings

import (
	"os"
	"path/filepath"
	"testing"
)

// Against the real tree: the count the report publishes has to be right.
func TestCountsTheRealTree(t *testing.T) {
	root := filepath.Join(os.Getenv("HOME"), "pgfuzz", "FINDINGS")
	fs, err := Scan(root)
	if err != nil {
		t.Skip("no FINDINGS here")
	}
	for _, f := range fs {
		if f.Name == ".git" {
			t.Fatal(".git counted as a finding -- this is the bug that made the headline 25 when it was 24")
		}
	}
	by := ByArea(fs)
	t.Logf("%d findings: %v", len(fs), by)

	// The reattributed leak must be counted where it belongs, not where its
	// directory name says.
	for _, f := range fs {
		if f.Name == "orioledb-vacuum-error-path-leak" {
			if f.Area != Core {
				t.Errorf("area = %q, want PostgreSQL core", f.Area)
			}
			if f.Override == "" {
				t.Error("the override must carry its reason")
			}
		}
	}
	per, systemic, unattributed := ByTarget(fs)
	t.Logf("by target: %v  systemic=%d unattributed=%d", per, systemic, unattributed)
}

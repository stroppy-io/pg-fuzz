package coverage

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPctIsZeroNotNaN(t *testing.T) {
	// A report that prints NaN teaches people to ignore the number.
	if got := (Counted{}).Pct(); got != 0 {
		t.Errorf("Pct on nothing = %v", got)
	}
}

// Newest per TARGET, not newest overall. A pass that re-measured six targets
// must not discard the seventeen from the pass before it -- and taking a
// single directory once reported one target's coverage as the campaign's.
func TestFindProfilesKeepsOneRunPerTarget(t *testing.T) {
	root := t.TempDir()
	mk := func(pass, target string, age time.Duration) string {
		d := filepath.Join(root, ".cov-parallel-"+pass, target, "upper", "dumps")
		os.MkdirAll(d, 0o755)
		p := filepath.Join(d, target+".profdata")
		os.WriteFile(p, []byte("x"), 0o644)
		when := time.Now().Add(-age)
		os.Chtimes(p, when, when)
		return p
	}
	mk("old", "alpha_fuzzer", 2*time.Hour)
	mk("old", "beta_fuzzer", 2*time.Hour)
	newAlpha := mk("new", "alpha_fuzzer", time.Minute)
	// merged.profdata is the union of a previous run and must never be an input.
	d := filepath.Join(root, ".cov-parallel-new", "alpha_fuzzer", "upper", "dumps")
	os.WriteFile(filepath.Join(d, "merged.profdata"), []byte("x"), 0o644)

	got, err := FindProfiles(root, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d profiles, want one per target: %v", len(got), got)
	}
	var sawNewAlpha bool
	for _, p := range got {
		if p == newAlpha {
			sawNewAlpha = true
		}
		if filepath.Base(p) == "merged.profdata" {
			t.Error("merged.profdata is a previous union, not an input")
		}
	}
	if !sawNewAlpha {
		t.Error("kept the older profile for a target that was re-measured")
	}
}

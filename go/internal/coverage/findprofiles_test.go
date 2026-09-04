package coverage

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func touch(t *testing.T, p string, age time.Duration) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	when := time.Now().Add(-age)
	if err := os.Chtimes(p, when, when); err != nil {
		t.Fatal(err)
	}
}

// -MEASURE AND -UNION MUST SEE THE SAME FILES.
//
// base-runner writes $OUT/dumps/<target>.profdata, which is where every
// profile this tool produces lands. FindProfiles globbed only
// .cov-parallel-*/<t>/upper/dumps/ -- a layout the deleted shell created and
// nothing in the port does. So -measure wrote profiles -union could not see:
// a union merged shell-era leftovers, or reported "no per-target profiles on
// disk" for a workspace that had just measured every target.
func TestFindProfilesReadsTheBuildDumps(t *testing.T) {
	root, build := t.TempDir(), t.TempDir()
	touch(t, filepath.Join(build, "dumps", "jsonb_fuzzer.profdata"), time.Minute)
	touch(t, filepath.Join(build, "dumps", "merged.profdata"), time.Minute)

	got, err := FindProfiles(root, build)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %v, want just the one per-target profile", got)
	}
	// merged.profdata is the union of the others and must never be an input.
	if filepath.Base(got[0]) != "jsonb_fuzzer.profdata" {
		t.Errorf("got %q", got[0])
	}
}

// THE OLD LAYOUT IS STILL READ. Sixteen of those directories exist on this
// host and their measurements are real; it is a fallback, not the source.
func TestFindProfilesStillReadsTheLegacyLayout(t *testing.T) {
	root, build := t.TempDir(), t.TempDir()
	touch(t, filepath.Join(root, ".cov-parallel-1", "geo_fuzzer", "upper",
		"dumps", "geo_fuzzer.profdata"), time.Hour)

	got, err := FindProfiles(root, build)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %v, want the legacy profile", got)
	}
}

// NEWEST PER TARGET, across both layouts: a fresh measurement must win over a
// shell-era leftover for the same target, or a union silently reports last
// month's coverage for it.
func TestFindProfilesPrefersTheNewestPerTarget(t *testing.T) {
	root, build := t.TempDir(), t.TempDir()
	old := filepath.Join(root, ".cov-parallel-1", "geo_fuzzer", "upper",
		"dumps", "geo_fuzzer.profdata")
	fresh := filepath.Join(build, "dumps", "geo_fuzzer.profdata")
	touch(t, old, 48*time.Hour)
	touch(t, fresh, time.Minute)

	got, err := FindProfiles(root, build)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != fresh {
		t.Errorf("got %v, want only the fresh profile %q", got, fresh)
	}
}

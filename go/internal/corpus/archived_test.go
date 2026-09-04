package corpus

import (
	"os"
	"path/filepath"
	"testing"
)

func mkdirf(t *testing.T, p, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// ARCHIVED INPUTS ARE STILL COVERAGE.
//
// minimize renames rather than deletes, so <t>.premin.<stamp> and
// <t>.capped.<stamp> hold real inputs that once reached real code. Seed walked
// only <ws>/corpus/<target>, so a coverage workspace measured the live corpus
// and never the archived reach -- roughly 641,000 inputs across two
// workspaces.
func TestSeedArchivedPicksUpBothConventions(t *testing.T) {
	ws, dst := t.TempDir(), t.TempDir()
	mkdirf(t, filepath.Join(ws, "corpus-backups", "jsonb_fuzzer.premin.20260101", "aaa"), "a")
	mkdirf(t, filepath.Join(ws, "corpus-backups", "jsonb_fuzzer.capped.20260202", "bbb"), "b")
	// Another target's archive must not be pulled in.
	mkdirf(t, filepath.Join(ws, "corpus-backups", "jsonpath_fuzzer.capped.20260202", "ccc"), "c")

	res, err := SeedArchived(ws, dst, []string{"jsonb_fuzzer"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Copied != 2 {
		t.Errorf("copied %d, want both archives of this target", res.Copied)
	}
	if _, err := os.Stat(filepath.Join(dst, "jsonb_fuzzer", "aaa")); err != nil {
		t.Error("the pre-minimise archive was not seeded")
	}
	if _, err := os.Stat(filepath.Join(dst, "jsonpath_fuzzer", "ccc")); err == nil {
		t.Error("another target's archive was pulled in")
	}
}

// A PREFIX MATCH ALONE IS WRONG: jsonb_fuzzer must not claim
// jsonb_fuzzer_extra's archives.
func TestBackupDirsMatchesTheWholeTargetName(t *testing.T) {
	ws := t.TempDir()
	mkdirf(t, filepath.Join(ws, "corpus-backups", "jsonb_fuzzer.capped.1", "x"), "x")
	mkdirf(t, filepath.Join(ws, "corpus-backups", "jsonb_fuzzer_extra.capped.1", "y"), "y")

	got := BackupDirs(ws, "jsonb_fuzzer")
	if len(got) != 1 {
		t.Fatalf("got %v, want only jsonb_fuzzer's own archive", got)
	}
}

// No backups at all is not an error: most workspaces have never been minimised.
func TestSeedArchivedWithNothingArchived(t *testing.T) {
	res, err := SeedArchived(t.TempDir(), t.TempDir(), []string{"a_fuzzer"})
	if err != nil || res.Copied != 0 {
		t.Errorf("SeedArchived = %+v, %v", res, err)
	}
}

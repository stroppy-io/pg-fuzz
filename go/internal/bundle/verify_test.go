package bundle

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A BYTE TOTAL CANNOT TELL A COMPLETE ARCHIVE FROM A SHORT ONE. Both are
// "some bytes". The shell counted the files from the SOURCE before taring and
// checked the archive against that number; the port replaced it with a byte
// count, which is exactly the check the original comment says does not work.
func TestArchiveIsVerifiedAgainstACountFromTheSource(t *testing.T) {
	src := t.TempDir()
	for _, n := range []string{"a", "b", "c"} {
		sub := filepath.Join(src, "t_fuzzer")
		if err := os.MkdirAll(sub, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(sub, n), []byte(n), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	stage := t.TempDir()
	note, err := ArchiveDirCounted(stage, "corpus/w1.tar.gz", src)
	if err != nil {
		t.Fatalf("ArchiveDirCounted: %v", err)
	}
	if note.Inputs != 3 {
		t.Errorf("counted %d inputs from the source, want 3", note.Inputs)
	}
	if note.Archived != 3 {
		t.Errorf("archive holds %d, want 3", note.Archived)
	}
	if !note.Verified {
		t.Error("a complete archive was not marked verified")
	}
	if note.Bytes == 0 {
		t.Error("no bytes written")
	}
}

// An unreadable entry must fail the archive rather than shrink it silently.
func TestUnreadableEntryFailsTheArchive(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can read anything")
	}
	src := t.TempDir()
	sub := filepath.Join(src, "t_fuzzer")
	os.MkdirAll(sub, 0o755)
	os.WriteFile(filepath.Join(sub, "ok"), []byte("x"), 0o644)
	bad := filepath.Join(sub, "locked")
	os.WriteFile(bad, []byte("x"), 0o000)

	_, err := ArchiveDirCounted(t.TempDir(), "corpus/w1.tar.gz", src)
	if err == nil {
		t.Fatal("an archive missing an unreadable entry reported success")
	}
	if !strings.Contains(err.Error(), "repair") && !strings.Contains(err.Error(), "short") {
		t.Errorf("unhelpful error: %v", err)
	}
}

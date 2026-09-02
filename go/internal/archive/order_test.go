package archive

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// The harness sources hash as every .c in name order THEN every .h in name
// order -- the byte order the shell that defined fp_version 2 used. Sorting
// both together interleaves them and produces a different hash from an
// identical configuration, which makes the next archive report that something
// moved when nothing did. That is the false alarm fp_version exists to prevent,
// so the order is part of the format, not a detail.
func TestHarnessHashOrdersDotCBeforeDotH(t *testing.T) {
	repo := t.TempDir()
	dir := filepath.Join(repo, "project", "fuzzer")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Names chosen so "sorted together" and ".c then .h" differ: a.h sorts
	// before b.c by name, but must hash after it.
	write := func(n, body string) {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("a.h", "HEADER\n")
	write("b.c", "SOURCE\n")

	want := sha256.Sum256([]byte("SOURCE\nHEADER\n")) // .c first
	bad := sha256.Sum256([]byte("HEADER\nSOURCE\n"))  // sorted together

	// HarnessHash reports a truncated digest; compare on that prefix.
	got := HarnessHash(repo)
	trunc := func(sum [32]byte) string { return hex.EncodeToString(sum[:])[:len(got)] }
	if got == trunc(bad) {
		t.Fatal("sources were sorted together; .c must hash before .h")
	}
	if got != trunc(want) {
		t.Errorf("HarnessHash = %s, want %s", got, trunc(want))
	}
}

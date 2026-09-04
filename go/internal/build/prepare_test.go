package build

import (
	"os"
	"path/filepath"
	"testing"
)

// A LEFTOVER BUILD DIRECTORY MUST NOT SURVIVE INTO THE NEXT BUILD.
//
// helper.py defaults to clean=False and logs "Keeping existing build artifacts
// as-is". On the happy path the move empties this directory, so it only bites
// after a build that failed or was interrupted part-way -- and then the
// previous ref's binaries survive and Targets() lists them as the new build's
// output.
func TestPrepareClearsALeftoverBuildDirectory(t *testing.T) {
	oss := t.TempDir()
	out := filepath.Join(oss, "build", "out", "pgfuzz-w")
	if err := os.MkdirAll(out, 0o755); err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(out, "jsonb_fuzzer")
	if err := os.WriteFile(stale, []byte("old binary"), 0o755); err != nil {
		t.Fatal(err)
	}

	if err := Prepare(oss, "pgfuzz-w", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stale); err == nil {
		t.Error("the previous build's binary survived into this build")
	}
}

// A DANGLING SYMLINK still goes, which is the case this code was written for:
// helper.py's makedirs raises FileExistsError on a path that exists and is not
// a directory, and the traceback never mentions a symlink.
func TestPrepareRemovesADanglingSymlink(t *testing.T) {
	oss := t.TempDir()
	outDir := filepath.Join(oss, "build", "out")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(outDir, "pgfuzz-w")
	if err := os.Symlink(filepath.Join(oss, "gone"), link); err != nil {
		t.Fatal(err)
	}
	if err := Prepare(oss, "pgfuzz-w", ""); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Lstat(link); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		t.Error("the dangling symlink survived")
	}
}

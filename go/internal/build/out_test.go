package build

import (
	"os"
	"path/filepath"
	"testing"
)

// A WORKSPACE'S OWN BUILD WINS OVER THE SHARED SYMLINK.
//
// build/out/<project> is one path every workspace's build points at in turn.
// The archive, fingerprint and inventory joined it directly, so a symlink
// another workspace had repointed yielded a manifest with the wrong fuzzer
// hashes, and a dangling one yielded a manifest with none.
func TestOutPrefersTheWorkspacesOwnBuild(t *testing.T) {
	oss, ws := t.TempDir(), t.TempDir()
	shared := filepath.Join(oss, "build", "out", "pgfuzz-w")
	own := filepath.Join(ws, "builds", "k")
	for _, d := range []string{shared, own} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if got := Out(oss, ws, "k", "pgfuzz-w"); got != own {
		t.Errorf("Out = %q, want the workspace's own build %q", got, own)
	}
	// No per-key build: the shared path is still right.
	if got := Out(oss, ws, "", "pgfuzz-w"); got != shared {
		t.Errorf("Out = %q, want the shared path %q", got, shared)
	}
	if got := Out(oss, ws, "missing", "pgfuzz-w"); got != shared {
		t.Errorf("Out = %q for an absent key, want the shared path", got)
	}
}

// A DANGLING SYMLINK IS REPORTED, not repaired: a reader wants to know its
// answer is empty because the build moved.
func TestOutDangling(t *testing.T) {
	oss := t.TempDir()
	outDir := filepath.Join(oss, "build", "out")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(outDir, "pgfuzz-w")
	if err := os.Symlink(filepath.Join(oss, "gone"), link); err != nil {
		t.Fatal(err)
	}
	if !OutDangling(oss, "pgfuzz-w") {
		t.Error("a dangling symlink was not reported")
	}
	// A real directory is not dangling.
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(link, 0o755); err != nil {
		t.Fatal(err)
	}
	if OutDangling(oss, "pgfuzz-w") {
		t.Error("a real build directory was called dangling")
	}
}

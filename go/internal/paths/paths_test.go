package paths

import (
	"os"
	"path/filepath"
	"testing"
)

// A binary installed outside any checkout must NOT resolve Home to something
// plausible-looking. It used to take three directories up unconditionally, so
// /usr/local/bin/pgfuzz gave "/" -- and the ratchet then read
// /scripts/ratchet-baseline.json, found nothing, and reported an empty
// baseline while exiting 0.
func TestNoCheckoutIsARefusalNotAGuess(t *testing.T) {
	dir := t.TempDir() // nothing that looks like the repo
	if got := findCheckout(filepath.Join(dir, "usr", "local", "bin")); got != "" {
		t.Errorf("want no checkout, got %q", got)
	}
	if _, err := (Roots{}).NeedHome(); err == nil {
		t.Error("an empty Home must be an error that says where it looked")
	}
}

func TestFindsTheCheckoutFromWithinIt(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "go", "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "go", "go.mod"), []byte("module pgfuzz\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// From <repo>/go/bin, where the built binary actually lives.
	if got := findCheckout(filepath.Join(root, "go", "bin")); got != root {
		t.Errorf("want %q, got %q", root, got)
	}
	// And from a deeper working directory inside it.
	deep := filepath.Join(root, "go", "internal", "paths")
	os.MkdirAll(deep, 0o755)
	if got := findCheckout(deep); got != root {
		t.Errorf("from a subdirectory: want %q, got %q", root, got)
	}
}

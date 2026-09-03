package main

import (
	"os"
	"path/filepath"
	"testing"
)

// A workspace directory becomes a docker bind mount, so it has to be
// absolute. Resolving `-w gt-pg17` from inside $PGFUZZ_WS matched the local
// directory first and returned a RELATIVE path, which docker rejects as a
// volume name -- "includes invalid characters for a local volume name ... If
// you intended to pass a host directory, use absolute path". The tool worked
// from one directory and not from the obvious one.
func TestOpenWSAlwaysReturnsAnAbsolutePath(t *testing.T) {
	ws := t.TempDir()
	t.Setenv("PGFUZZ_WS", ws)
	if err := os.MkdirAll(filepath.Join(ws, "w1"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ws, "w1", "workspace.conf"),
		[]byte("name=w1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Stand inside the workspace root, exactly as somebody would.
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(cwd)
	if err := os.Chdir(ws); err != nil {
		t.Fatal(err)
	}

	dir, _, _, err := openWS("w1")
	if err != nil {
		t.Fatalf("openWS: %v", err)
	}
	if !filepath.IsAbs(dir) {
		t.Errorf("openWS returned %q; a bind mount needs an absolute path", dir)
	}
}

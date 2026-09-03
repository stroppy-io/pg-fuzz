package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// corpus_globs= was the fourth workspace key the port recorded and never read,
// after plugins=, patch= and preload=. It exists because a workspace can fuzz
// a 265-file patch for eleven hours and touch none of it: the patch ships its
// own regression SQL, and without that SQL in the seed corpus nothing ever
// reaches the code it added.
func TestSeedFromSourceUsesTheWorkspaceGlobs(t *testing.T) {
	home, ws := t.TempDir(), t.TempDir()
	t.Setenv("PGFUZZ_HOME", home)
	t.Setenv("PGFUZZ_WS", ws)

	write := func(p, body string) {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(home, "project", "build.sh"), "#!/bin/sh\n")
	write(filepath.Join(ws, "w1", "workspace.conf"),
		"name=w1\nref=R\ncorpus_globs=contrib/mypatch/sql/*.sql\n")

	// A source tree carrying regression SQL only under the extra glob.
	src := t.TempDir()
	write(filepath.Join(src, "src", "test", "regress", "sql", "base.sql"),
		"SELECT 1;\n")
	write(filepath.Join(src, "contrib", "mypatch", "sql", "extra.sql"),
		"SELECT patched_function_only_here();\n")

	o := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	code := cmdCorpus([]string{"-w", "w1", "-seed-from-source", src})
	w.Close()
	os.Stdout = o
	b, _ := io.ReadAll(r)
	out := string(b)

	if code != 0 {
		t.Fatalf("seeding failed (%d):\n%s", code, out)
	}
	if !strings.Contains(out, "corpus_globs from the workspace") {
		t.Errorf("the workspace's corpus_globs was ignored:\n%s", out)
	}
}

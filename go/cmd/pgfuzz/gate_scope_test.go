package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// RoundComplete asks "did every built target run". Handing it the newest log
// per target with no time bound answers a different question: a target that
// last ran a week ago counts as swept, so the gate written to catch a short
// round passed every short round. The old check carried an explicit --since
// because round numbers restart and a shorter campaign leaves the previous
// one's logs in place.
func TestGateScopesToARoundWhenAsked(t *testing.T) {
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
	write(filepath.Join(home, "scripts", "ubsan-baseline.tsv"), "#\n")
	write(filepath.Join(ws, "w1", "workspace.conf"), "name=w1\nref=R\n")

	healthy := "#1000 INITED cov: 1 ft: 1 corp: 1/1b\n" +
		"Done 500000 runs in 10 second(s)\n"
	fresh := filepath.Join(ws, "w1", "artifacts", "a_fuzzer", "run-new.log")
	stale := filepath.Join(ws, "w1", "artifacts", "b_fuzzer", "run-old.log")
	write(fresh, healthy)
	write(stale, healthy)
	old := time.Now().Add(-14 * 24 * time.Hour)
	if err := os.Chtimes(stale, old, old); err != nil {
		t.Fatal(err)
	}

	run := func(args ...string) string {
		t.Helper()
		o := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w
		cmdGate(args)
		w.Close()
		os.Stdout = o
		b, _ := io.ReadAll(r)
		return string(b)
	}

	// Unscoped: the two-week-old log still counts, and the gate says so
	// rather than implying the verdict covers this round.
	out := run("-w", "w1")
	if !strings.Contains(out, "of any age") {
		t.Errorf("an unscoped run must say its verdict is unscoped:\n%s", out)
	}

	// Scoped to a day: only the fresh log is judged.
	out = run("-w", "w1", "-since", "24h")
	if !strings.Contains(out, "judging 1 of 2") {
		t.Errorf("-since did not drop the two-week-old log:\n%s", out)
	}
}

package main

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// THIS TESTS THE COMMAND, NOT THE LIBRARY, and that distinction is the whole
// point of it. ratchet.Check has always supported an acknowledgement list and
// internal/ratchet has a passing test for the Acknowledged outcome -- but the
// only caller passed nil, so the outcome was unreachable and the `known` branch
// was dead code. A target somebody had written a row for would have regressed
// the round every round forever, which is exactly what teaches people to
// ignore a gate. A green library suite said nothing about it.
func TestRatchetCommandHonoursTheAcknowledgementList(t *testing.T) {
	home, ws := t.TempDir(), t.TempDir()
	t.Setenv("PGFUZZ_HOME", home)
	t.Setenv("PGFUZZ_WS", ws)

	mk := func(p string) {
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write := func(p, body string) {
		mk(filepath.Dir(p))
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// A workspace whose only target ran far below its floor.
	write(filepath.Join(ws, "w1", "workspace.conf"), "name=w1\nref=REL_17_10\n")
	write(filepath.Join(ws, "w1", "artifacts", "numeric_fuzzer", "run-20260903-000000.log"),
		"#1000 INITED cov: 10 ft: 20 corp: 5/100b\n"+
			"Done 100 runs in 10 second(s)\n"+
			"stat::number_of_executed_units: 100\n")

	base := map[string]any{
		"version":   2,
		"tolerance": 0.1,
		"floors":    map[string]map[string]int{"w1": {"numeric_fuzzer": 100000}},
		"regimes":   map[string]map[string]string{"w1": {"numeric_fuzzer": "jobs=1"}},
	}
	b, _ := json.MarshalIndent(base, "", "  ")
	write(filepath.Join(home, "scripts", "ratchet-baseline.json"), string(b))
	write(filepath.Join(home, "project", "build.sh"), "#!/bin/sh\n") // marks the checkout

	run := func() (int, string) {
		t.Helper()
		old := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w
		code := cmdRatchet([]string{"-w", "w1"})
		w.Close()
		os.Stdout = old
		out, _ := io.ReadAll(r)
		return code, string(out)
	}

	// No acknowledgement: 100 against a floor of 100,000 must fail.
	write(filepath.Join(home, "scripts", "known-starved.tsv"), "# no rows\n")
	if code, out := run(); code == 0 {
		t.Fatalf("a target at 0.1%% of its floor passed; output:\n%s", out)
	}

	// Acknowledged: the same run must now pass, and say why.
	write(filepath.Join(home, "scripts", "known-starved.tsv"),
		"# acknowledged\nnumeric_fuzzer\tharness is starved upstream\tFINDINGS/x\t2026-09-03\n")
	code, out := run()
	if code != 0 {
		t.Errorf("an acknowledged target still failed the round (exit %d); output:\n%s", code, out)
	}
	if !strings.Contains(out, "known") {
		t.Errorf("output does not report the acknowledgement:\n%s", out)
	}
}

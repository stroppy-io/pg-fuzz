package logs

import (
	"os"
	"path/filepath"
	"testing"
)

// ParseSweep's only target delimiter was the SHELL's banner, "fuzzing <t> for
// <n>s". The Go sweep prints "---- <t> ---- (i/n)", so a Go sweep log
// redirected to sweep-roundN.log parsed to an empty map -- and the ratchet,
// told to read a round log, reported "nothing was checked" and exited 2. It
// failed closed, which is the right direction, but the round was unjudgeable.
func TestParseSweepReadsBothBanners(t *testing.T) {
	dir := t.TempDir()
	body := "" +
		"  ---- jsonb_fuzzer ---- (1/2)\n" +
		"Done 1000 runs in 10 second(s)\n" +
		"stat::number_of_executed_units: 1000\n" +
		"stat::new_units_added:          7\n" +
		"fuzzing regex_fuzzer for 45s\n" +
		"Done 2000 runs in 10 second(s)\n" +
		"stat::number_of_executed_units: 2000\n" +
		"stat::new_units_added:          3\n"
	p := filepath.Join(dir, "sweep-round1.log")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	per, err := ParseSweep(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(per) != 2 {
		t.Fatalf("parsed %d targets, want 2: %v", len(per), per)
	}
	if per["jsonb_fuzzer"].Execs != 1000 {
		t.Errorf("go-format banner: execs = %d, want 1000", per["jsonb_fuzzer"].Execs)
	}
	if per["regex_fuzzer"].Execs != 2000 {
		t.Errorf("shell-format banner: execs = %d, want 2000", per["regex_fuzzer"].Execs)
	}
}

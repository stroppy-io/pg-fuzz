package fuzz

import (
	"os"
	"path/filepath"
	"testing"
)

// A reproducer written into the run's scratch overlay must reach the artifacts
// directory. It did not: libFuzzer's -artifact_prefix pointed at the overlay,
// the next run of that target deleted it, and the count came from a directory
// nothing wrote to -- so a run that found six crashes reported "artifacts +0".
func TestHarvestMovesReproducersOutOfScratch(t *testing.T) {
	upper, arts := t.TempDir(), t.TempDir()
	write := func(dir, name string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, n := range []string{"crash-abc", "leak-def", "timeout-ghi", "oom-jkl"} {
		write(upper, n)
	}
	// Not evidence: run_fuzzer's own output directory and a stray file.
	if err := os.Mkdir(filepath.Join(upper, "t_libfuzzer_address_out"), 0o755); err != nil {
		t.Fatal(err)
	}
	write(upper, "fuzz-0.log")

	if got := harvest(upper, arts); got != 4 {
		t.Errorf("harvest moved %d, want 4", got)
	}
	for _, n := range []string{"crash-abc", "leak-def", "timeout-ghi", "oom-jkl"} {
		if _, err := os.Stat(filepath.Join(arts, n)); err != nil {
			t.Errorf("%s did not reach the artifacts directory", n)
		}
		if _, err := os.Stat(filepath.Join(upper, n)); err == nil {
			t.Errorf("%s was left in scratch, where the next run deletes it", n)
		}
	}
	if _, err := os.Stat(filepath.Join(upper, "fuzz-0.log")); err != nil {
		t.Error("harvest took a file that is not a reproducer")
	}
	if got := countArtifacts(arts); got != 4 {
		t.Errorf("countArtifacts = %d, want 4 -- the count the series records", got)
	}
}

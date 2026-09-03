package logs

import (
	"os"
	"path/filepath"
	"testing"
)

// The report carries a "Dictionaries: N/M" line whose field had no writer, so
// it read 0/M forever. A structured-format target without a dictionary
// saturates fast, which is a fact about the run worth seeing rather than
// assuming.
func TestParseRegimeReadsTheDictionaryFlag(t *testing.T) {
	dir := t.TempDir()
	with := filepath.Join(dir, "with.log")
	without := filepath.Join(dir, "without.log")

	inv := "/out/jsonb_fuzzer -- -rss_limit_mb=2560 -timeout=25 -max_total_time=45 " +
		"-jobs=8 -workers=8 -max_len=4096 -detect_leaks=0 -artifact_prefix=/out/ " +
		"/tmp/jsonb_fuzzer_corpus"
	if err := os.WriteFile(with, []byte(inv+" -dict=/out/jsonb_fuzzer.dict\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(without, []byte(inv+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	r, err := ParseRegime(with)
	if err != nil {
		t.Fatal(err)
	}
	if !r.Dict {
		t.Error("a run launched with -dict was recorded as having none")
	}
	if r.Jobs != 8 {
		t.Errorf("Jobs = %d, want 8 -- the regime must survive the change", r.Jobs)
	}

	r, err = ParseRegime(without)
	if err != nil {
		t.Fatal(err)
	}
	if r.Dict {
		t.Error("a run with no dictionary was recorded as having one")
	}
}

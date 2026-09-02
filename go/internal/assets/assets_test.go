package assets

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The binary must carry everything a build needs, and nothing that is config.
func TestCarriesTheToolAndNotTheConfig(t *testing.T) {
	files, err := List()
	if err != nil {
		t.Fatal(err)
	}
	need := []string{
		"build.sh", "Dockerfile", "project.yaml",
		"add_fuzzers.diff", "guc_file_nul.diff",
		"fuzzer/simple_query_fuzzer.c", "fuzzer/fuzz_util.h",
	}
	have := map[string]bool{}
	for _, f := range files {
		have[f] = true
	}
	for _, n := range need {
		if !have[n] {
			t.Errorf("missing from the binary: %s", n)
		}
	}
	// Config must NOT be baked: a new plugin version would otherwise need a
	// new binary. See the package comment.
	for _, n := range []string{"plugins.tsv"} {
		if have[n] {
			t.Errorf("%s is config and must not be embedded", n)
		}
	}
	var harnesses int
	for _, f := range files {
		if strings.HasPrefix(f, "fuzzer/") && strings.HasSuffix(f, "_fuzzer.c") {
			harnesses++
		}
	}
	if harnesses < 20 {
		t.Errorf("only %d harnesses embedded; expected the full set", harnesses)
	}
	t.Logf("%d files, %d harnesses", len(files), harnesses)
}

func TestMaterialiseWritesARunnableTree(t *testing.T) {
	dir := t.TempDir()
	if err := Materialise(dir); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(filepath.Join(dir, "build.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode()&0o111 == 0 {
		t.Error("build.sh is not executable; the image build would fail on it")
	}
	if _, err := os.Stat(filepath.Join(dir, "fuzzer", "fuzz_util.h")); err != nil {
		t.Errorf("harness headers missing: %v", err)
	}
}

package corpus

import (
	"os"
	"path/filepath"
	"testing"
)

// A FAULT IS NOT A DUPLICATE.
//
// Seed counted "already present" and "could not be copied" in one `skipped`
// counter, printed as "N already present", and exited 0. So a source half of
// which could not be read seeded half a corpus and reported success.
func TestSeedSeparatesFailuresFromDuplicates(t *testing.T) {
	src, dst := t.TempDir(), t.TempDir()
	mk := func(root, target, name string, mode os.FileMode) string {
		d := filepath.Join(root, target)
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(d, name)
		if err := os.WriteFile(p, []byte(name), mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	mk(src, "jsonb_fuzzer", "aaa", 0o644) // copies
	mk(src, "jsonb_fuzzer", "bbb", 0o644) // already present below
	mk(dst, "jsonb_fuzzer", "bbb", 0o644)
	unreadable := mk(src, "jsonb_fuzzer", "ccc", 0o000) // cannot be read

	res, err := SeedInto(src, dst)
	if err != nil {
		t.Fatal(err)
	}
	if res.Copied != 1 {
		t.Errorf("copied %d, want 1", res.Copied)
	}
	if res.Present != 1 {
		t.Errorf("present %d, want 1", res.Present)
	}
	if os.Geteuid() == 0 {
		t.Skip("running as root: an unreadable file is still readable")
	}
	if res.Failed != 1 {
		t.Errorf("failed %d, want 1 for %s", res.Failed, unreadable)
	}
	if res.FirstErr == nil {
		t.Error("a failure was counted with no reason recorded")
	}
}

// The int-returning Seed keeps working for callers that only want totals, and
// still folds failures into skipped -- but nothing reports success off it now.
func TestSeedTotalsStillAddUp(t *testing.T) {
	src, dst := t.TempDir(), t.TempDir()
	d := filepath.Join(src, "a_fuzzer")
	os.MkdirAll(d, 0o755)
	os.WriteFile(filepath.Join(d, "x"), []byte("x"), 0o644)

	copied, skipped, err := Seed(src, dst)
	if err != nil || copied != 1 || skipped != 0 {
		t.Errorf("Seed = %d, %d, %v", copied, skipped, err)
	}
}

// SUBDIRECTORIES ARE STILL INPUTS.
//
// The shell copied with `cp -rn "$src/corpus/."`, which recurses. Seed skipped
// any directory inside a target directory. Nothing writes nested corpus
// entries today, so this was latent -- but a seed that silently drops part of
// a corpus is the failure this file is about, and depth is not a reason to
// skip.
func TestSeedIsRecursive(t *testing.T) {
	src, dst := t.TempDir(), t.TempDir()
	deep := filepath.Join(src, "a_fuzzer", "nested")
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(deep, "x"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "a_fuzzer", "y"), []byte("y"), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := SeedInto(src, dst)
	if err != nil {
		t.Fatal(err)
	}
	if res.Copied != 2 {
		t.Errorf("copied %d, want both the top-level and the nested input", res.Copied)
	}
	if _, err := os.Stat(filepath.Join(dst, "a_fuzzer", "nested", "x")); err != nil {
		t.Error("the nested input was dropped")
	}
}

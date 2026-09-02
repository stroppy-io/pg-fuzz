package incontainer

import (
	"os"
	"path/filepath"
	"testing"
)

// The first version of this walk read `u+rwX,go+rX` as "0755 for directories,
// 0644 for everything else". That is wrong, and wrong in the one way that
// matters: X also applies to files that are ALREADY executable, which under
// /out means every fuzz target. Handing a build back would have left 23
// unrunnable binaries and nothing would have said so until a run failed.
func TestChownKeepsExecutablesExecutable(t *testing.T) {
	root := t.TempDir()
	targ := filepath.Join(root, "xlogreader_fuzzer")
	data := filepath.Join(root, "seed")
	sub := filepath.Join(root, "corpus")
	if err := os.WriteFile(targ, []byte("ELF"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(data, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}

	// Chown to the uid we already have, so this needs no privilege.
	failed, err := Chown(root, os.Getuid(), os.Getgid())
	if err != nil || failed != 0 {
		t.Fatalf("Chown: %v, %d failed", err, failed)
	}

	for _, c := range []struct {
		path string
		want os.FileMode
		why  string
	}{
		{targ, 0o755, "an already-executable file keeps its execute bit"},
		{data, 0o644, "a plain file becomes readable, not executable"},
		{sub, 0o755, "a directory stays traversable"},
	} {
		fi, err := os.Stat(c.path)
		if err != nil {
			t.Fatal(err)
		}
		if got := fi.Mode().Perm(); got != c.want {
			t.Errorf("%s: mode %o, want %o (%s)", filepath.Base(c.path), got, c.want, c.why)
		}
	}
}

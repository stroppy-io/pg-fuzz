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
	failed, err := Chown(root, os.Getuid(), os.Getgid(), true)
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

// A BUILD is handed back ownership-only, and this is the test that would have
// saved a two-hour campaign. $OUT holds the prepared PostgreSQL data
// directory, which must be 0700 or 0750 -- PostgreSQL FATALs on anything with
// other-bits set. Reusing the corpus rule (u+rwX,go+rX) widened it to 0755 and
// killed every backend-initialised target: protocol_fuzzer,
// simple_query_fuzzer, spi_query_fuzzer, backend_types_fuzzer and
// extension_funcs_fuzzer executed nothing at all, while every other number in
// the run looked healthy.
func TestChownOwnOnlyPreservesADataDirectory(t *testing.T) {
	root := t.TempDir()
	data := filepath.Join(root, "data")
	if err := os.Mkdir(data, 0o700); err != nil {
		t.Fatal(err)
	}
	conf := filepath.Join(data, "postgresql.conf")
	if err := os.WriteFile(conf, []byte("# conf\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(root, "a_fuzzer")
	if err := os.WriteFile(bin, []byte("ELF"), 0o755); err != nil {
		t.Fatal(err)
	}

	if failed, err := Chown(root, os.Getuid(), os.Getgid(), false); err != nil || failed != 0 {
		t.Fatalf("Chown: %v, %d failed", err, failed)
	}

	if fi, _ := os.Stat(data); fi.Mode().Perm() != 0o700 {
		t.Errorf("data directory is %o, want 0700 -- PostgreSQL refuses other-bits",
			fi.Mode().Perm())
	}
	if fi, _ := os.Stat(conf); fi.Mode().Perm() != 0o600 {
		t.Errorf("postgresql.conf is %o, want 0600", fi.Mode().Perm())
	}
	// The fuzz target must still be runnable.
	if fi, _ := os.Stat(bin); fi.Mode().Perm()&0o100 == 0 {
		t.Errorf("the target lost its execute bit: %o", fi.Mode().Perm())
	}
}

// The corpus still gets the widening it was written for: the unreadable-corpus
// bug was files the host user could not open.
func TestChownWidenStillOpensACorpus(t *testing.T) {
	root := t.TempDir()
	seed := filepath.Join(root, "seed")
	if err := os.WriteFile(seed, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Chown(root, os.Getuid(), os.Getgid(), true); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(seed); fi.Mode().Perm() != 0o644 {
		t.Errorf("corpus entry is %o, want 0644", fi.Mode().Perm())
	}
}

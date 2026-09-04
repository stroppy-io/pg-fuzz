package main

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The archive WRITER had no caller: archive.NewManifest, TarCorpus,
// FuzzerHashes, ReproducerCounts and Fingerprint were all ported and there was
// no `archive` command. The READER survived, so the campaign history page was
// permanently frozen at whatever the deleted shell had written and a new run
// could never appear on it.
func TestArchiveWritesASealedRunTheIndexCanRead(t *testing.T) {
	home, ws := t.TempDir(), t.TempDir()
	t.Setenv("PGFUZZ_HOME", home)
	t.Setenv("PGFUZZ_WS", ws)
	t.Setenv("PGFUZZ_CACHE", t.TempDir())

	write := func(p, body string) {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(home, "project", "build.sh"), "#!/bin/sh\n")
	write(filepath.Join(home, "project", "fuzzer", "a_fuzzer.c"), "int main(){}\n")

	slugDir := filepath.Join(ws, "campaigns", "demo")
	write(filepath.Join(slugDir, "series.jsonl"),
		`{"ws":"w1","target":"a_fuzzer","execs":10}`+"\n")
	man := `{"slug":"demo","sealed":true,"entries":[{"workspace":"w1","build_ok":true,"targets":["a_fuzzer"]}]}`
	write(filepath.Join(slugDir, "MANIFEST.json"), man)
	write(filepath.Join(slugDir, "ws", "w1", "corpus", "a_fuzzer", "seed1"), "x")
	write(filepath.Join(slugDir, "ws", "w1", "corpus", "a_fuzzer", "seed2"), "y")

	o := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	code := cmdArchive([]string{"-slug", "demo"})
	w.Close()
	os.Stdout = o
	b, _ := io.ReadAll(r)
	out := string(b)

	if code != 0 {
		t.Fatalf("archive failed (%d):\n%s", code, out)
	}

	// The seal makes the directory unremovable, so t.TempDir's own cleanup
	// fails on it. Unsealing here is the test tidying up after a guard that
	// worked, not a workaround for one that did not.
	t.Cleanup(func() {
		filepath.WalkDir(slugDir, func(p string, d os.DirEntry, err error) error {
			if err == nil {
				os.Chmod(p, 0o755)
			}
			return nil
		})
	})

	runs, _ := filepath.Glob(filepath.Join(slugDir, "demo-*"))
	if len(runs) != 1 {
		t.Fatalf("expected one run directory, got %v", runs)
	}
	run := runs[0]

	// The manifest the index reads.
	mb, err := os.ReadFile(filepath.Join(run, "MANIFEST.json"))
	if err != nil {
		t.Fatalf("no manifest in the run: %v", err)
	}
	var got struct {
		ConfigFingerprint string `json:"config_fingerprint"`
		FPVersion         int    `json:"fp_version"`
		Corpus            map[string]struct {
			Inputs   int  `json:"inputs"`
			Verified bool `json:"verified"`
		} `json:"corpus"`
	}
	if err := json.Unmarshal(mb, &got); err != nil {
		t.Fatal(err)
	}
	if got.ConfigFingerprint == "" || got.FPVersion == 0 {
		t.Errorf("manifest has no fingerprint: %s", mb)
	}
	// Counted independently BEFORE the tar and checked after: an archive short
	// by a few files looks exactly like a complete one.
	if c := got.Corpus["w1"]; c.Inputs != 2 || !c.Verified {
		t.Errorf("corpus note = %+v, want 2 inputs verified", c)
	}

	// WRITE-ONCE. The index page asserts this on the directory's behalf; until
	// now nothing enforced it.
	//
	// ROOT IGNORES THE MODE BITS, and CI containers run as root, so this
	// cannot be checked there -- a 0555 directory is writable to uid 0. The
	// seal is still applied; what cannot be observed is the refusal.
	if os.Geteuid() != 0 {
		if err := os.WriteFile(filepath.Join(run, "probe"), []byte("x"), 0o644); err == nil {
			t.Error("the run directory is writable; the seal did not hold")
		}
	}
	if !strings.Contains(out, "sealed") {
		t.Errorf("archive did not report sealing:\n%s", out)
	}
}

// An archive of a campaign still adding to itself is an archive of nothing.
func TestArchiveRefusesALiveCampaign(t *testing.T) {
	home, ws := t.TempDir(), t.TempDir()
	t.Setenv("PGFUZZ_HOME", home)
	t.Setenv("PGFUZZ_WS", ws)

	write := func(p, body string) {
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, []byte(body), 0o644)
	}
	write(filepath.Join(home, "project", "build.sh"), "#!/bin/sh\n")
	slugDir := filepath.Join(ws, "campaigns", "live")
	write(filepath.Join(slugDir, "series.jsonl"), "\n")
	write(filepath.Join(slugDir, "MANIFEST.json"), `{"slug":"live","entries":[]}`)
	b, _ := json.Marshal(map[string]any{"slug": "live", "pid": os.Getpid()})
	write(filepath.Join(slugDir, "live", "campaign.json"), string(b))

	if code := cmdArchive([]string{"-slug", "live"}); code == 0 {
		t.Error("a running campaign was archived")
	}
}

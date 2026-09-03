package campaign

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func write(t *testing.T, p, s string) {
	t.Helper()
	if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
}

// CORRECT FIRST, FAST SECOND.
//
// A cache that answers from a file that has moved on is the same class of
// defect as everything else in this repository: a confident, wrong number. The
// key is size and mtime together, and the series is append-only, so any new
// slice changes the size.
func TestReadCachedSeesAnAppend(t *testing.T) {
	p := filepath.Join(t.TempDir(), "series.jsonl")
	write(t, p, `{"ws":"a","target":"t","execs":1}`+"\n")
	s := Series{Path: p}

	first, err := s.ReadCached()
	if err != nil || len(first) != 1 {
		t.Fatalf("first read: %v %d", err, len(first))
	}
	// A second read of an unchanged file must not re-parse, and must agree.
	again, _ := s.ReadCached()
	if len(again) != 1 {
		t.Fatalf("second read returned %d rows", len(again))
	}

	// Appending must be seen. mtime resolution can be coarse, so the size
	// change is what has to carry this -- which is the point of keying on both.
	write(t, p, `{"ws":"a","target":"t","execs":1}`+"\n"+
		`{"ws":"b","target":"t","execs":2}`+"\n")
	after, err := s.ReadCached()
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != 2 {
		t.Fatalf("after an append the cache returned %d rows, want 2 -- it went stale",
			len(after))
	}
	if after[1].Workspace != "b" {
		t.Errorf("second row = %q, want the appended one", after[1].Workspace)
	}
}

// A REWRITE AT THE SAME SIZE must also be seen, which is what the mtime half
// of the key is for.
func TestReadCachedSeesARewrite(t *testing.T) {
	p := filepath.Join(t.TempDir(), "series.jsonl")
	write(t, p, `{"ws":"aaa","target":"t"}`+"\n")
	s := Series{Path: p}
	if rows, _ := s.ReadCached(); len(rows) != 1 || rows[0].Workspace != "aaa" {
		t.Fatal("first read")
	}

	time.Sleep(10 * time.Millisecond)
	write(t, p, `{"ws":"bbb","target":"t"}`+"\n") // same length, different content
	rows, err := s.ReadCached()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Workspace != "bbb" {
		t.Errorf("after a same-size rewrite the cache returned %v -- it went stale", rows)
	}
}

// It agrees with the uncached read, which is the only reason it is allowed to
// exist.
func TestReadCachedAgreesWithRead(t *testing.T) {
	p := filepath.Join(t.TempDir(), "series.jsonl")
	write(t, p, `{"ws":"a","target":"t","execs":7}`+"\n"+
		`{"ws":"b","target":"u","execs":9}`+"\n")
	s := Series{Path: p}

	want, err := s.Read()
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.ReadCached()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) {
		t.Fatalf("cached %d rows, uncached %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("row %d differs:\n cached   %+v\n uncached %+v", i, got[i], want[i])
		}
	}
}

// A missing file is an error, not an empty campaign held from a previous read.
func TestReadCachedMissingFile(t *testing.T) {
	s := Series{Path: filepath.Join(t.TempDir(), "nope.jsonl")}
	if _, err := s.ReadCached(); err == nil {
		t.Error("a missing series returned no error")
	}
}

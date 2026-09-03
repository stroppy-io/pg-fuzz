package fuzz

import (
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"pgfuzz/internal/logs"
	"testing"
)

// Slice logs run to gigabytes and gzip takes about fifty to one on them. The
// shell compressed every one; the port left them raw, which is also how
// `pgfuzz tidy` came to compress them later behind the readers' backs.
func TestGzipInPlaceReplacesTheLogAndKeepsIt(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "run-1.log")
	body := "#1000 INITED cov: 1 ft: 1 corp: 1/1b\nDone 42 runs in 1 second(s)\n"
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := gzipInPlace(p); err != nil {
		t.Fatalf("gzipInPlace: %v", err)
	}
	if _, err := os.Stat(p); err == nil {
		t.Error("the uncompressed log was left behind")
	}
	f, err := os.Open(p + ".gz")
	if err != nil {
		t.Fatalf("no compressed log: %v", err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != body {
		t.Errorf("round trip lost content:\n%q", got)
	}
	// And the parser must read it back, since every gate reads through it.
	st, err := logs.ParseFile(p + ".gz")
	if err != nil {
		t.Fatalf("the compressed log is unreadable: %v", err)
	}
	if st.Execs != 42 {
		t.Errorf("execs = %d, want 42", st.Execs)
	}
}

// A half-written .gz beside a deleted .log would lose the slice's only
// durable record, which is the thing the log exists to be.
func TestGzipInPlaceLeavesNoPartial(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "run-1.log")
	os.WriteFile(p, []byte("x\n"), 0o644)
	if err := gzipInPlace(p); err != nil {
		t.Fatal(err)
	}
	if m, _ := filepath.Glob(filepath.Join(dir, "*.partial")); len(m) > 0 {
		t.Errorf("left a partial: %v", m)
	}
}

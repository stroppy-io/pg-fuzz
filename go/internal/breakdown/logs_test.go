package breakdown

import (
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
)

// Scan globbed run-*.log.gz ONLY, while the census globbed run-*.log ONLY --
// the two halves of the port reading one directory and disagreeing about
// which files are in it. The runner writes .log and `pgfuzz tidy` turns it
// into .log.gz, so either is normal, and a reader that sees one of them
// silently reports on half the evidence.
func TestScanReadsBothCompressedAndPlainLogs(t *testing.T) {
	ws := t.TempDir()
	dir := filepath.Join(ws, "artifacts", "xlogreader_fuzzer")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	report := "==1==ERROR: AddressSanitizer: heap-buffer-overflow\n" +
		"    #0 0x1 in DecodeXLogRecord /src/postgres/bld/../src/backend/access/transam/xlogreader.c:1952:3\n" +
		"SUMMARY: AddressSanitizer: heap-buffer-overflow\n"

	if err := os.WriteFile(filepath.Join(dir, "run-1.log"), []byte(report), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(filepath.Join(dir, "run-2.log.gz"))
	if err != nil {
		t.Fatal(err)
	}
	zw := gzip.NewWriter(f)
	zw.Write([]byte(report))
	zw.Close()
	f.Close()

	got := Scan(ws, nil)
	if len(got) == 0 {
		t.Fatal("nothing was attributed; both log forms were missed")
	}
	// One crash in each file, both credited to core.
	if n := got["core"]["xlogreader_fuzzer"]; n != 2 {
		t.Errorf("core/xlogreader = %d, want 2 (one plain log, one gzipped)", n)
	}
}

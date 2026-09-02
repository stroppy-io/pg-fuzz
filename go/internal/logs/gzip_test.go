package logs

import (
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
)

// `pgfuzz tidy` compresses any log over 10 MB older than an hour, including
// the ones the runner writes. ParseFile read only plain files, so tidying a
// workspace silently blinded the ratchet, the starvation gate and the
// round-completeness gate at once -- and an empty gate exits 0. On the machine
// this was found on: 113,705 .log.gz against 425 .log.
func TestParseFileReadsGzippedLogs(t *testing.T) {
	dir := t.TempDir()
	body := "#1000 INITED cov: 10 ft: 20 corp: 5/100b\n" +
		"Done 4242 runs in 10 second(s)\n" +
		"stat::number_of_executed_units: 4242\n"

	plain := filepath.Join(dir, "run-1.log")
	if err := os.WriteFile(plain, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	gz := filepath.Join(dir, "run-2.log.gz")
	f, err := os.Create(gz)
	if err != nil {
		t.Fatal(err)
	}
	zw := gzip.NewWriter(f)
	if _, err := zw.Write([]byte(body)); err != nil {
		t.Fatal(err)
	}
	zw.Close()
	f.Close()

	want, err := ParseFile(plain)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseFile(gz)
	if err != nil {
		t.Fatalf("a compressed log could not be read: %v", err)
	}
	if got.Execs != want.Execs || got.Execs != 4242 {
		t.Errorf("gzipped log parsed to %d executions, plain to %d, want 4242",
			got.Execs, want.Execs)
	}
}

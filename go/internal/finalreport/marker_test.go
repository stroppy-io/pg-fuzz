package finalreport

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A READER WITH NO WRITER IS NOT A FEATURE.
//
// ReadStoppedAt parsed this file, MarkerPath said where it lives, and the
// bundle inventory listed it among the documents a campaign leaves behind --
// while nothing in the program ever wrote one. The final report's "stopped at"
// was therefore blank for every campaign this tool has run.
func TestMarkerRoundTrips(t *testing.T) {
	path := filepath.Join(t.TempDir(), "campaign-stopped.marker")
	when := time.Date(2026, 9, 3, 8, 0, 10, 0, time.UTC)

	err := WriteStopMarker(path, when, []CorpusCount{
		{Workspace: "gt-pg17", Target: "jsonb_fuzzer", Inputs: 4},
		{Workspace: "gt-pg17", Target: "binary_recv_fuzzer", Inputs: 11629},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := ReadStoppedAt(path); got != "2026-09-03 08:00:10" {
		t.Errorf("ReadStoppedAt = %q, want the time it was written with", got)
	}

	b, _ := os.ReadFile(path)
	body := string(b)
	// The corpus sizes AT THE MOMENT OF STOP, which is what lets somebody
	// check that a bundle's corpus is the one its numbers were measured on.
	if !strings.Contains(body, "corpus\tgt-pg17\tbinary_recv_fuzzer\t11629") {
		t.Errorf("the corpus snapshot is missing:\n%s", body)
	}
	// Sorted, because this file is diffed between runs.
	if i, j := strings.Index(body, "binary_recv"), strings.Index(body, "jsonb"); i > j {
		t.Error("rows are not sorted; the file will reorder itself between runs")
	}
}

// Absent stays absent: a missing marker must read as empty, not as a zero
// time, or a campaign that never stopped becomes one that stopped in year one.
func TestMarkerAbsentReadsEmpty(t *testing.T) {
	if got := ReadStoppedAt(filepath.Join(t.TempDir(), "nope")); got != "" {
		t.Errorf("ReadStoppedAt on a missing file = %q, want empty", got)
	}
}

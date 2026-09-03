package coverage

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// summary.json is left behind by the PREVIOUS run, so a replay that dies or
// half-completes leaves the older file in place -- and reading it back records
// a number no run produced. That is how a round once recorded coverage DOWN
// 6.8% from a binary that had not changed: llvm-cov reports only the files
// present in the profile, so an incomplete profile loses denominator as well
// as covered lines. A coverage point that silently substitutes the previous
// run's number is worse than a missing one, because it looks like data.
func TestMeasureRefusesASummaryFromAnEarlierRun(t *testing.T) {
	out := t.TempDir()
	sum := filepath.Join(out, "report_target", "a_fuzzer", "linux", "summary.json")
	if err := os.MkdirAll(filepath.Dir(sum), 0o755); err != nil {
		t.Fatal(err)
	}
	body := `{"data":[{"totals":{"lines":{"count":100,"covered":40,"percent":40}}}]}`
	if err := os.WriteFile(sum, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	// Stale by an hour: written long before this run began.
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(sum, old, old); err != nil {
		t.Fatal(err)
	}

	// helper.py will fail here (no oss-fuzz clone); the point is that even
	// with a readable, well-formed summary present, a stale one is refused.
	_, err := Measure(context.Background(), MeasureRequest{
		OSSFuzz: t.TempDir(), Project: "p", Target: "a_fuzzer",
		Corpus: t.TempDir(), Out: out, Sanitizer: "coverage",
	})
	if err == nil {
		t.Fatal("a summary from an earlier run was accepted as a measurement")
	}
	if !strings.Contains(err.Error(), "predates this run") {
		t.Errorf("refusal does not name the cause: %v", err)
	}
}

// Measuring a build instrumented for crashes reports numbers that mean
// nothing, so it is refused rather than measured.
func TestMeasureRefusesANonCoverageBuild(t *testing.T) {
	_, err := Measure(context.Background(), MeasureRequest{Sanitizer: "address"})
	if err == nil || !strings.Contains(err.Error(), "-sanitizer coverage") {
		t.Errorf("an address build was measured: %v", err)
	}
}

// summary.json is overwritten by the next run, so a file replaced each time
// carries no trend -- and "has coverage stopped growing" is the question.
func TestRecordTargetAppendsATrend(t *testing.T) {
	p := filepath.Join(t.TempDir(), "coverage-series.jsonl")
	for i, covered := range []int{40, 55} {
		s := TargetSummary{
			Target: "a_fuzzer", When: time.Now().UTC(),
			Lines: Counts{Count: 100, Covered: covered},
		}
		if err := RecordTarget(p, "w1", s); err != nil {
			t.Fatalf("row %d: %v", i, err)
		}
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d rows, want 2 -- the series must accumulate", len(lines))
	}
	var last struct {
		WS     string `json:"ws"`
		Target string `json:"target"`
		Lines  Counts `json:"lines"`
	}
	if err := json.Unmarshal([]byte(lines[1]), &last); err != nil {
		t.Fatal(err)
	}
	if last.WS != "w1" || last.Target != "a_fuzzer" || last.Lines.Covered != 55 {
		t.Errorf("last row = %+v", last)
	}
}

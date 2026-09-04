package fuzz

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A MONITORING LOOP MUST NOT DIE OF THE THING IT MONITORS NOT HAVING HAPPENED
// YET.
//
// The shell's sampler ran under `set -e`, its first grep found no progress
// line because libFuzzer had not printed one, and it exited on iteration one
// leaving an empty file -- measured 2026-08-31. Every read here tolerates
// absence.
func TestSampleBeforeAnyProgressLine(t *testing.T) {
	log := filepath.Join(t.TempDir(), "run.log")
	if err := os.WriteFile(log, []byte("INFO: Seed: 1\nINFO: Loaded 1 modules\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	s := sampleLog(log, "jsonb_fuzzer", time.Now().Add(-30*time.Second), 12.5)

	if s.Target != "jsonb_fuzzer" || s.CPUSec != 12.5 {
		t.Errorf("the sample lost its own fields: %+v", s)
	}
	if s.DT < 25 {
		t.Errorf("dt = %d, want the seconds since the slice started", s.DT)
	}
	// NOUGHT EXECUTIONS AND "NO LINE YET" ARE DIFFERENT FACTS, which is why
	// these are pointers: this file exists to make a stall visible.
	if s.Execs != nil || s.Cov != nil {
		t.Errorf("fields libFuzzer has not printed were reported as values: %+v", s)
	}
	// And a missing log is not a crash.
	if got := sampleLog(filepath.Join(t.TempDir(), "nope"), "t", time.Now(), 0); got.Target != "t" {
		t.Error("a missing log broke the sampler")
	}
}

// THE NEWEST LINE WINS, from the tail rather than the whole file: these logs
// run to gigabytes.
func TestSampleTakesTheNewestProgressLine(t *testing.T) {
	log := filepath.Join(t.TempDir(), "run.log")
	body := "#1024 NEW cov: 100 ft: 200 corp: 10/1Kb rss: 120Mb\n" +
		"#2048 NEW cov: 150 ft: 260 corp: 12/2Kb rss: 300Mb\n"
	if err := os.WriteFile(log, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	s := sampleLog(log, "t", time.Now(), 0)
	if s.Execs == nil || *s.Execs != 2048 {
		t.Errorf("execs = %v, want the newest line's 2048", s.Execs)
	}
	if s.Cov == nil || *s.Cov != 150 {
		t.Errorf("cov = %v, want 150", s.Cov)
	}
	if s.RSSMB == nil || *s.RSSMB != 300 {
		t.Errorf("rss = %v, want 300", s.RSSMB)
	}
}

// THE ROWS KEEP ARRIVING whether or not the fuzzer has anything to say -- the
// gaps are the signal. A null field must survive the write as null, not as 0.
func TestAppendSampleKeepsAbsenceAbsent(t *testing.T) {
	p := filepath.Join(t.TempDir(), "run.samples.jsonl")
	n := 7
	AppendSample(p, Sample{T: 1, DT: 0, Target: "t", CPUSec: 1.5})
	AppendSample(p, Sample{T: 2, DT: 15, Target: "t", CPUSec: 3.0, Execs: &n})

	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	lines := 0
	for _, ln := range splitLinesTest(string(b)) {
		if ln == "" {
			continue
		}
		lines++
		var row map[string]any
		if err := json.Unmarshal([]byte(ln), &row); err != nil {
			t.Fatalf("row %d is not json: %v\n%s", lines, err, ln)
		}
		if lines == 1 && row["execs"] != nil {
			t.Errorf("an unprinted field was written as %v, want null", row["execs"])
		}
		if lines == 2 && row["execs"] != float64(7) {
			t.Errorf("execs = %v, want 7", row["execs"])
		}
	}
	if lines != 2 {
		t.Errorf("wrote %d rows, want 2 -- the cadence is the point", lines)
	}
}

// The samples sit beside the log they describe.
func TestSamplePathIsBesideTheLog(t *testing.T) {
	if got := SamplePath("/w/artifacts/t/run-20260101-fuzz-0.log"); got !=
		"/w/artifacts/t/run-20260101-fuzz-0.samples.jsonl" {
		t.Errorf("SamplePath = %q", got)
	}
}

func splitLinesTest(s string) []string {
	var out []string
	start := 0
	for i, c := range s {
		if c == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

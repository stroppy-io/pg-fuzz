package gate

import (
	"path/filepath"
	"testing"
)

// A GATE FAILURE HAS TO SURVIVE THE TERMINAL.
//
// The shell appended every per-round verdict to a file and the live feed
// tailed it. The port printed to stderr and wrote nothing, so a regression
// found in round 3 of an overnight campaign existed only in scrollback: the
// report could not mention it and the bundle could not ship it.
func TestFailuresRoundTrip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "gate-failures.jsonl")

	for _, f := range []Failure{
		{Round: 3, Workspace: "gt-pg17", Gate: "ratchet", Detail: "a floor was not met"},
		{Round: 4, Workspace: "gt-pg17", Gate: "skipped", Detail: "the disk floor cut jsonb_fuzzer"},
	} {
		if err := Record(p, f); err != nil {
			t.Fatal(err)
		}
	}

	got, err := ReadFailures(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("read %d failures, want 2", len(got))
	}
	if got[0].Gate != "ratchet" || got[0].Round != 3 || got[0].Workspace != "gt-pg17" {
		t.Errorf("first row lost information: %+v", got[0])
	}
	// Stamped, because "a gate failed" without a time cannot be placed in a
	// campaign that ran for two days.
	if got[0].At == "" {
		t.Error("no timestamp recorded")
	}
	// Appended, not overwritten: round 4 must not erase round 3.
	if got[1].Round != 4 {
		t.Errorf("second row is %+v; the file was overwritten", got[1])
	}
}

// NO FILE MEANS NO FAILURE, which is what most campaigns should produce. An
// error here would make a clean run look broken.
func TestReadFailuresAbsentIsClean(t *testing.T) {
	got, err := ReadFailures(filepath.Join(t.TempDir(), "nope.jsonl"))
	if err != nil {
		t.Errorf("a missing file errored: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("got %v from a missing file", got)
	}
}

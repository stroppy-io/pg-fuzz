package tui

import (
	"strings"
	"testing"
	"time"

	"pgfuzz/internal/campaign"
	"pgfuzz/internal/term"
)

// SILENT IS COUNTED SEPARATELY.
//
// A slice that reported no executions is not a slice that ran badly -- it is a
// slice whose numbers cannot be used, and the ratchet skips it. Folding the two
// together makes a round of 23 look complete when four of it are unusable, and
// silence was detected only at gate time, which is after the round.
func TestSliceStatsCountsSilenceSeparately(t *testing.T) {
	started := time.Now().Add(-2 * time.Hour)
	rows := []campaign.Slice{
		{Workspace: "w", Target: "a_fuzzer", Execs: 1000, Alive: true, Corpus: 100, CorpusBefore: 40},
		{Workspace: "w", Target: "b_fuzzer", Execs: 0, Alive: false, Corpus: 140, CorpusBefore: 100},
		{Workspace: "w", Target: "c_fuzzer", Execs: 2000, Alive: true, Corpus: 240, CorpusBefore: 140},
	}
	s := SliceStats(rows, 2, started, time.Now())

	if s.Finished != 3 {
		t.Errorf("finished %d, want 3", s.Finished)
	}
	if s.Silent != 1 {
		t.Errorf("silent %d, want 1 -- the ratchet cannot use that slice", s.Silent)
	}
	if s.InFlight != 2 {
		t.Errorf("in flight %d, want 2", s.InFlight)
	}
	// Corpus is a LEVEL, not an increment: the newest per workspace, not a sum.
	if s.CorpusNow != 240 {
		t.Errorf("corpus %d, want the newest level 240, not a sum", s.CorpusNow)
	}
	// Grown 40 -> 240 over two hours.
	if s.CorpusRate < 90 || s.CorpusRate > 110 {
		t.Errorf("rate %.0f/hour, want about 100", s.CorpusRate)
	}
}

// A RUN TOO YOUNG TO HAVE A RATE CLAIMS NONE, rather than dividing by a few
// seconds and reporting a number that swings by orders of magnitude.
func TestSliceStatsWithNoElapsedTime(t *testing.T) {
	now := time.Now()
	s := SliceStats([]campaign.Slice{
		{Workspace: "w", Execs: 10, Alive: true, Corpus: 100, CorpusBefore: 1},
	}, 0, now, now)
	if s.CorpusRate != 0 {
		t.Errorf("rate %.0f from a run with no elapsed time", s.CorpusRate)
	}
}

// The panel says SILENT in words, because it is the number that invalidates
// the others.
func TestSlicesPanelNamesSilence(t *testing.T) {
	var scr term.Screen
	scr.Reset(20, 120)
	scr.Plain = true
	drawSlices(&scr, Model{SliceStats: Slices{Finished: 23, Silent: 4}}, 1)
	got := scr.Text()
	if !strings.Contains(got, "SILENT") || !strings.Contains(got, "ratchet cannot use") {
		t.Errorf("the panel does not explain silence:\n%s", got)
	}
	// Nothing to say draws nothing.
	var empty term.Screen
	empty.Reset(20, 120)
	empty.Plain = true
	if drawSlices(&empty, Model{}, 1) != 1 {
		t.Error("an empty campaign drew a slices line")
	}
}

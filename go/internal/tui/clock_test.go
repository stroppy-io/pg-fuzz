package tui

import (
	"pgfuzz/internal/term"
	"strings"
	"testing"
	"time"
)

// A MISSING START TIME IS NOT A DURATION. The zero check guarded one branch of
// Elapsed and not the other, so a campaign with slices but no recorded start
// subtracted from year one, and the header printed "elapsed 2562047h47m" -- a
// clamped maximum dressed as a measurement.
func TestElapsedWithoutAStart(t *testing.T) {
	m := Model{LastSlice: time.Now()}
	if got := m.Elapsed(); got != 0 {
		t.Errorf("Elapsed = %v, want 0 when nothing recorded the start", got)
	}
	if got := headerClock(m); !strings.Contains(got, "unknown") {
		t.Errorf("headerClock = %q, want it to say the start is unknown", got)
	}
	// And zero is not printed as a measurement either: a run with 29 finished
	// slices did not take no time.
	if strings.Contains(headerClock(m), "0h00m") {
		t.Error("a missing start must not render as elapsed 0h00m")
	}
}

// The ordinary case still measures.
func TestElapsedFinishedCampaign(t *testing.T) {
	start := time.Now().Add(-3 * time.Hour)
	m := Model{Started: start, LastSlice: start.Add(2 * time.Hour)}
	if got := m.Elapsed(); got != 2*time.Hour {
		t.Errorf("Elapsed = %v, want 2h from start to last slice", got)
	}
	if got := headerClock(m); !strings.Contains(got, "elapsed 2h00m") {
		t.Errorf("headerClock = %q, want elapsed 2h00m", got)
	}
}

// A SNAPSHOT CLAIMS NO SELECTION, and does not depend on a code GitHub's log
// viewer is undocumented for. Reverse video marks the row the arrow keys are
// on; in a log there are no arrow keys, so the highlight asserts a state that
// cannot exist. Everything else in the frame degrades gracefully if a viewer
// ignores it -- an unsupported dim is still readable text.
func TestSnapshotDropsSelectionAndKeys(t *testing.T) {
	m := Model{
		Slug: "ci", Phase: "SWEEPING",
		Rows: []Row{{Name: "ci-rel_17_stable-undefined"}},
		Err:  "docker unreachable",
	}
	draw := func(snap bool) string {
		m.Snapshot = snap
		var s term.Screen
		s.Plain = true
		Draw(&s, m, Grid, 0, 24, 200)
		return s.Text()
	}

	live := draw(false)
	if !strings.Contains(live, term.Reverse) {
		t.Error("an interactive frame must still highlight the selected row")
	}
	if !strings.Contains(live, "q quit") {
		t.Error("an interactive frame must still show the keys")
	}

	snap := draw(true)
	if strings.Contains(snap, term.Reverse) {
		t.Error("a snapshot must not claim a selection")
	}
	if strings.Contains(snap, "q quit") {
		t.Error("a snapshot must not offer keys nobody can press")
	}
	// The half of the footer that still matters does print.
	if !strings.Contains(snap, "docker unreachable") {
		t.Error("a snapshot must still report what went wrong reading docker")
	}
}

package tui

import (
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

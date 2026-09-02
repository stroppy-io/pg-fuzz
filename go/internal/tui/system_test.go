package tui

import (
	"testing"
	"time"
)

// The first reading in a process has no predecessor to difference against, so
// it must not be reported as a measurement. "cpu 0%" on a fully busy machine
// is worse than saying nothing.
func TestFirstCPUReadingIsNotAMeasurement(t *testing.T) {
	cpuPrev.total, cpuPrev.idle = 0, 0
	if got := CPUPercent(); got != nil {
		t.Errorf("first call returned %v, want nil", *got)
	}
	// A second call taken IMMEDIATELY may still be nil, and that is correct:
	// /proc/stat moves in clock ticks, and no ticks between two reads means
	// there is nothing to divide by. Reporting 0% there would say the machine
	// is idle when the truth is that no time passed.
	//
	// Given real time, it measures.
	time.Sleep(120 * time.Millisecond)
	got := CPUPercent()
	if got == nil {
		t.Fatal("no measurement after 120ms; utilisation should be readable")
	}
	if *got < 0 || *got > 100 {
		t.Errorf("utilisation out of range: %v", *got)
	}
}

// The warning is the point of the line. A machine that has run out of disk
// stops campaigns, and that has to be visible without reading the numbers.
func TestStatusLineLeadsWithTheWarningThatEndsACampaign(t *testing.T) {
	for _, tc := range []struct {
		name string
		s    SystemStats
		want string
	}{
		{"disk", SystemStats{FreeG: 5, CPUs: 8}, "DISK LOW"},
		{"io", SystemStats{FreeG: 500, Blocked: 9, CPUs: 8}, "blocked on I/O"},
		{"load", SystemStats{FreeG: 500, Load: 40, CPUs: 8}, "oversubscribed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := StatusLine(tc.s); !contains(got, tc.want) {
				t.Errorf("want %q in %q", tc.want, got)
			}
		})
	}
	// A healthy machine gets no warning at all.
	if got := StatusLine(SystemStats{FreeG: 500, Load: 4, CPUs: 8}); contains(got, "--") &&
		(contains(got, "DISK LOW") || contains(got, "oversubscribed")) {
		t.Errorf("healthy machine warned: %q", got)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

package logs

import (
	"strings"
	"testing"
)

// THE ONLY MEMORY SIGNAL A SLICE PRODUCES.
//
// PeakRSS was parsed since this package was written and consumed by nothing.
// It is what distinguishes a target growing toward an OOM kill from one that
// is merely slow -- a distinction that otherwise arrives as a dead container
// with no explanation.
func TestPeakRSSIsTheHighestSeen(t *testing.T) {
	log := strings.Join([]string{
		"#1024 NEW    cov: 100 ft: 200 corp: 10/1Kb rss: 120Mb",
		"#2048 NEW    cov: 110 ft: 220 corp: 11/2Kb rss: 980Mb",
		"#4096 NEW    cov: 120 ft: 240 corp: 12/3Kb rss: 512Mb",
		"Done 4096 runs in 30 second(s)",
	}, "\n")

	s := Parse(strings.NewReader(log))
	if s.PeakRSS != 980 {
		t.Errorf("PeakRSS = %d, want the highest seen (980), not the last", s.PeakRSS)
	}
}

// A log with no rss line reports none rather than zero-as-a-measurement: some
// targets never print one, and 0 MB resident is not a thing that happens.
func TestPeakRSSAbsent(t *testing.T) {
	s := Parse(strings.NewReader("Done 10 runs in 1 second(s)\n"))
	if s.PeakRSS != 0 {
		t.Errorf("PeakRSS = %d for a log with no rss line", s.PeakRSS)
	}
}

package logs

import (
	"strings"
	"testing"
)

// A SLICE CUT MID-RUN HAS NOT "NEVER FUZZED".
//
// "Done N runs" and the stat:: block are both printed when a run ENDS, and
// `-on-deadline cut` ends a campaign's clock mid-slice by design. The log then
// reported zero executions for a target that had done six hundred thousand,
// and the starvation gate failed a real CI item with "started but never
// fuzzed" about a log whose last line is "#613474 REDUCE ... exec/s: 20449".
func TestCutSliceCountsItsProgress(t *testing.T) {
	log := "Running with entropic power schedule\n" +
		"#1000 INITED cov: 1 ft: 1 corp: 1/1b\n" +
		"#613474 REDUCE cov: 2506 ft: 4270 corp: 196/8080b lim: 4096 exec/s: 20449 rss: 117Mb\n"
	s := Parse(strings.NewReader(log))
	if s.Execs != 613474 {
		t.Fatalf("Execs = %d, want the progress counter 613474", s.Execs)
	}
	if !s.Partial {
		t.Error("a count taken from a progress line is a lower bound and must say so")
	}
	if got := s.Startup(); got != Fuzzed {
		t.Errorf("Startup = %v, want fuzzed", got)
	}
}

// AND THE REPLAY ALONE IS STILL NOT FUZZING. "#1000 INITED" is the corpus
// replay finishing; counting it would collapse the state this package keeps
// apart on purpose.
func TestInitedAloneIsNotProgress(t *testing.T) {
	s := Parse(strings.NewReader("#1000 INITED cov: 1 ft: 1 corp: 1/1b\n"))
	if s.Execs != 0 {
		t.Fatalf("Execs = %d, want 0 -- INITED is replay, not fuzzing", s.Execs)
	}
	if s.Startup() != Inited {
		t.Errorf("Startup = %v, want inited", s.Startup())
	}
}

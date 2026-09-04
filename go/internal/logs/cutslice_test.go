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

// A WARNING IS NOT AN ABORT. libFuzzer prints
//
//	WARNING: no interesting inputs were found so far. Is the code instrumented...
//
// whenever the seed corpus is small, and then fuzzes normally. A bare substring
// match on "no interesting inputs were found" caught it, so numeric_fuzzer --
// 204,128 executions across two finishing workers -- was reported as having
// aborted on its initial corpus and failed a healthy sweep item. Any target
// with a one-file seed corpus could trip it on any run.
func TestStartupWarningIsNotAnAbort(t *testing.T) {
	healthy := "INFO: seed corpus: files: 1 min: 21b max: 21b total: 21b rss: 65Mb\n" +
		"#1\tINITED exec/s: 0 rss: 65Mb\n" +
		"WARNING: no interesting inputs were found so far. Is the code instrumented for coverage?\n" +
		"#204128\tDONE cov: 900 ft: 2000 corp: 100/1000b\n" +
		"Done 204128 runs in 31 second(s)\n"
	s := Parse(strings.NewReader(healthy))
	if s.Aborted {
		t.Error("a startup WARNING must not read as an abort")
	}
	if s.Execs != 204128 {
		t.Errorf("Execs = %d, want 204128", s.Execs)
	}

	// The fatal forms still count, prefix and all.
	for _, fatal := range []string{
		"==1==ERROR: libFuzzer: no interesting inputs were found\n",
		"==1==ERROR: libFuzzer: a leak has been found in the initial corpus\n",
	} {
		if !Parse(strings.NewReader(fatal)).Aborted {
			t.Errorf("must still recognise the abort: %q", fatal)
		}
	}
}

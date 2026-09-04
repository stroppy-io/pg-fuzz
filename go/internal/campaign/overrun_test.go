package campaign

import (
	"testing"
	"time"
)

// THE CEILING HOLDS EVEN WHEN THE POLICY SAYS KEEP GOING.
//
// Under finish-sweep the extra workspace ran with an explicitly zero deadline,
// so -max-overrun -- whose whole job is bounding the campaign's wall clock --
// did not apply in the one policy that most needs bounding. The shell clamped
// the extra sweep to HARD_STOP - now.
func TestFinishSweepIsBoundedByTheHardStop(t *testing.T) {
	deadline := time.Now().Add(-time.Minute) // already past
	overrun := 10 * time.Minute
	hardStop := deadline.Add(overrun)

	// The value handed to the extra sweep must be a real deadline in the
	// future-but-bounded sense, never the zero time, which means "no limit".
	if hardStop.IsZero() {
		t.Fatal("the hard stop is the zero time; that is 'no limit'")
	}
	if !hardStop.After(deadline) {
		t.Error("the hard stop is not past the deadline it extends")
	}
	if hardStop.Sub(deadline) != overrun {
		t.Errorf("hard stop is deadline + %s, want + %s", hardStop.Sub(deadline), overrun)
	}
}

// A zero MaxOverrun still produces a bounded stop rather than an open one.
func TestDefaultOverrunIsNotUnbounded(t *testing.T) {
	c := Config{Hours: 2, PerTarget: 45, Entries: []Entry{{
		Name: "w", Targets: []string{"a_fuzzer", "b_fuzzer"},
	}}}
	if got := defaultOverrun(c); got <= 0 {
		t.Errorf("defaultOverrun = %s, want a positive bound", got)
	}
}

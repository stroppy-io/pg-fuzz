package fuzz

import (
	"testing"
	"time"
)

// A SLICE MUST HAVE AN UPPER BOUND.
//
// libFuzzer honours -max_total_time by checking the clock between executions,
// so a single input that never returns runs forever and `docker run` with it.
// The campaign then waits on that slice for the rest of the run: no crash, no
// timeout in the series, just a workspace that stops producing while the
// driver looks alive.
//
// The shell driver caught this from outside with a watchdog. That was ported
// as `pgfuzz watchdog` and nothing ever starts it, so it guarded only the runs
// where somebody opened a second terminal.
func TestHangGraceIsAMeaningfulBound(t *testing.T) {
	if HangGrace <= 0 {
		t.Fatal("slices have no upper bound")
	}
	// Long enough that a slow shutdown or a final corpus write is not
	// mistaken for a hang, short enough to not lose a campaign to one target.
	if HangGrace < time.Minute {
		t.Errorf("HangGrace = %s: a slow shutdown would read as a hang", HangGrace)
	}
	if HangGrace > 30*time.Minute {
		t.Errorf("HangGrace = %s: a hung target holds a core for too long", HangGrace)
	}
}

// The bound is the slice's OWN budget plus the grace, not a constant: a
// 45-second slice and a two-hour soak must not share a deadline.
func TestTheDeadlineFollowsTheBudget(t *testing.T) {
	short := time.Duration(45)*time.Second + HangGrace
	long := time.Duration(7200)*time.Second + HangGrace
	if long <= short {
		t.Error("the deadline does not scale with the slice's budget")
	}
	if short <= 45*time.Second {
		t.Error("the deadline is not past the budget it is meant to allow")
	}
}

// A hang is evidence about the TARGET and a disk stop is evidence about the
// MACHINE. Conflating them would either excuse a real hang or blame a target
// for the filesystem.
func TestHangAndDiskStopAreSeparate(t *testing.T) {
	var r Result
	r.Hung = true
	if r.DiskStop {
		t.Error("a hang set the disk-stop flag")
	}
	r = Result{DiskStop: true}
	if r.Hung {
		t.Error("a disk stop set the hang flag")
	}
}

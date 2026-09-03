package campaign

import (
	"context"
	"strings"
	"testing"
	"time"
)

// The campaign must run the gates after each workspace's sweep. The port lost
// this entirely: the shell spliced `ratchet check` then `ratchet update` into
// every workspace-round, and in Go nothing invoked the ratchet at all, so
// floors never rose and no regression was ever detected unless a human typed
// the command. campaign/run.go contained a comment mentioning the ratchet and
// no call.
func TestAfterSweepRunsForEachWorkspace(t *testing.T) {
	var seen []string
	c := Config{
		Hours: 0.0001, PerTarget: 1, Jobs: 1,
		Entries: []Entry{
			{Name: "w1", Dir: "/nonexistent/w1", Targets: []string{"a_fuzzer"}},
			{Name: "w2", Dir: "/nonexistent/w2", Targets: []string{"a_fuzzer"}},
		},
		OnDeadline: FinishRound,
		AfterSweep: func(e Entry, round int, complete bool, _ string) { seen = append(seen, e.Name) },
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_ = Run(ctx, c)

	if len(seen) < 2 {
		t.Fatalf("AfterSweep fired %d time(s) for 2 workspaces: %v", len(seen), seen)
	}
	got := map[string]bool{}
	for _, n := range seen {
		got[n] = true
	}
	for _, want := range []string{"w1", "w2"} {
		if !got[want] {
			t.Errorf("no gate ran for %s", want)
		}
	}
}

// A sweep cut short by the deadline must not be judged. Bounding the clock
// must not manufacture findings: a workspace that got through six of its
// targets has not earned a verdict on the other seventeen.
func TestAfterSweepReportsAShortRound(t *testing.T) {
	var complete []bool
	c := Config{
		Hours: 0.0001, PerTarget: 1, Jobs: 1,
		// Three targets that cannot run: the sweep records none of them.
		Entries: []Entry{{Name: "w1", Dir: "/nonexistent/w1",
			Targets: []string{"a_fuzzer", "b_fuzzer", "c_fuzzer"}}},
		OnDeadline: FinishRound,
		AfterSweep: func(e Entry, round int, ok bool, _ string) { complete = append(complete, ok) },
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_ = Run(ctx, c)

	if len(complete) == 0 {
		t.Fatal("AfterSweep never fired")
	}
	if complete[0] {
		t.Error("a sweep that ran none of its targets was reported as complete")
	}
}

// A COMPLETE ROUND CAN STILL BE UNJUDGEABLE.
//
// Every target ran, so nothing above notices -- while one slice was stopped
// part-way by the disk floor and produced a number that says nothing about the
// target. Gating on "complete" alone hands that number to the ratchet, which
// reads it as a regression in the target rather than as a fact about the
// filesystem.
func TestDiskCutRoundIsNotJudgeable(t *testing.T) {
	var gotComplete bool
	var gotReason string
	seen := 0

	c := Config{
		AfterSweep: func(e Entry, round int, complete bool, notJudgeable string) {
			seen++
			gotComplete, gotReason = complete, notJudgeable
		},
	}
	// Stand in for what runSweep computes: the round finished, and one of its
	// slices was cut.
	reason := reasonNotJudgeable(true, []string{"jsonb_fuzzer"})
	if c.AfterSweep != nil {
		c.AfterSweep(Entry{Name: "w"}, 1, true, reason)
	}

	if seen != 1 {
		t.Fatalf("hook called %d times", seen)
	}
	if !gotComplete {
		t.Error("the round was complete and was reported otherwise")
	}
	if gotReason == "" {
		t.Error("a complete round with a disk-cut slice was judged anyway")
	}
	if !strings.Contains(gotReason, "jsonb_fuzzer") {
		t.Errorf("the reason does not name the cut slice: %q", gotReason)
	}
}

// Nothing wrong means nothing to say, and the gates run.
func TestCleanRoundIsJudgeable(t *testing.T) {
	if got := reasonNotJudgeable(true, nil); got != "" {
		t.Errorf("a clean complete round reported %q; the gates must run", got)
	}
	// A short round still stops them, and says which reason it was.
	if got := reasonNotJudgeable(false, nil); got == "" {
		t.Error("a short round was judged anyway")
	}
}

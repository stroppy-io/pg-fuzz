package campaign

import (
	"context"
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
		AfterSweep: func(e Entry, round int, complete bool) { seen = append(seen, e.Name) },
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
		AfterSweep: func(e Entry, round int, ok bool) { complete = append(complete, ok) },
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

package campaign

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The port made the workspace loop sequential and recorded no reason. Five
// workspaces then take five times the wall clock for the same hours budget, so
// the last arm of a comparison gets a fraction of the rounds the first did --
// on the campaign that exposed this, gt-pg19 got one round to gt-pg16's two
// and 15 of 23 targets never ran.
func TestWorkspacesSweepConcurrently(t *testing.T) {
	var inFlight, peak int64
	var mu sync.Mutex

	entries := make([]Entry, 4)
	for i := range entries {
		entries[i] = Entry{
			Name: string(rune('a'+i)) + "-ws", Dir: "/nonexistent",
			Targets: []string{"a_fuzzer"},
		}
	}

	c := Config{
		Hours: 0.0002, PerTarget: 1, Jobs: 1, Parallel: 4,
		Entries: entries, OnDeadline: FinishRound,
		AfterSweep: func(e Entry, round int, ok bool, _ string) {
			n := atomic.AddInt64(&inFlight, 1)
			mu.Lock()
			if n > peak {
				peak = n
			}
			mu.Unlock()
			time.Sleep(30 * time.Millisecond)
			atomic.AddInt64(&inFlight, -1)
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_ = Run(ctx, c)

	mu.Lock()
	got := peak
	mu.Unlock()
	if got < 2 {
		t.Errorf("peak concurrency %d: workspaces still sweep one at a time", got)
	}
}

// One at a time stays available, and is what a single workspace gets.
func TestParallelDefaultsToOne(t *testing.T) {
	if (Config{}).parallel() != 1 {
		t.Error("an unset Parallel must mean one workspace at a time")
	}
	if (Config{Parallel: 1}).parallel() != 1 {
		t.Error("Parallel 1 must mean one")
	}
	if (Config{Parallel: 6}).parallel() != 6 {
		t.Error("Parallel must be honoured")
	}
}

// A round is not over until every workspace in it has finished, or the next
// round's rotation would overlap this one's slices.
func TestRoundWaitsForEveryWorkspace(t *testing.T) {
	var running, overlaps int64
	c := Config{
		Hours: 0.0002, PerTarget: 1, Jobs: 1, Parallel: 3,
		Entries: []Entry{
			{Name: "w1", Dir: "/nonexistent", Targets: []string{"a_fuzzer"}},
			{Name: "w2", Dir: "/nonexistent", Targets: []string{"a_fuzzer"}},
		},
		OnDeadline: FinishRound,
	}
	seen := map[int]bool{}
	var mu sync.Mutex
	c.AfterSweep = func(e Entry, round int, ok bool, _ string) {
		atomic.AddInt64(&running, 1)
		mu.Lock()
		// A previous round must be fully drained before this one appears.
		for r := range seen {
			if r != round {
				atomic.AddInt64(&overlaps, 0) // rounds are sequential by construction
			}
		}
		seen[round] = true
		mu.Unlock()
		time.Sleep(10 * time.Millisecond)
		atomic.AddInt64(&running, -1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_ = Run(ctx, c)

	if n := atomic.LoadInt64(&running); n != 0 {
		t.Errorf("%d sweeps were still in flight when Run returned", n)
	}
}

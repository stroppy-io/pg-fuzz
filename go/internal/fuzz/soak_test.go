package fuzz

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// A soak keeps a POOL in flight and refills it, rather than walking targets in
// order. The port had no soak at all, and it was not on the deliberate-drop
// list.
func TestSoakKeepsAPoolInFlight(t *testing.T) {
	var peak, cur int64
	var mu sync.Mutex

	targets := make([]string, 12)
	for i := range targets {
		targets[i] = "t" + string(rune('a'+i)) + "_fuzzer"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	Soak(ctx, SoakRequest{
		// A build that does not exist: Run fails fast, which is all this
		// test needs -- the question is the SCHEDULE, not the fuzzing.
		Request:    Request{Workspace: t.TempDir(), OutDir: t.TempDir(), Seconds: 1},
		Targets:    targets,
		Concurrent: 4, Multiplier: 1,
		Deadline: time.Now().Add(20 * time.Second),
		OnStart: func(string, int) {
			n := atomic.AddInt64(&cur, 1)
			mu.Lock()
			if n > peak {
				peak = n
			}
			mu.Unlock()
			time.Sleep(20 * time.Millisecond)
			atomic.AddInt64(&cur, -1)
		},
	})

	mu.Lock()
	got := peak
	mu.Unlock()
	if got < 2 {
		t.Errorf("peak concurrency %d: the pool is not a pool", got)
	}
	if got > 4 {
		t.Errorf("peak concurrency %d exceeds the pool size of 4", got)
	}
}

// A soak slice is long and mostly useful work; cutting one in half to honour a
// clock throws away the replay it already paid for. The deadline stops at a
// slice boundary -- a sweep cuts, because its slices are short and its promise
// is about when the machine is free.
func TestSoakStopsAtASliceBoundary(t *testing.T) {
	var started int64
	targets := make([]string, 50)
	for i := range targets {
		targets[i] = "t_fuzzer"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	Soak(ctx, SoakRequest{
		Request:    Request{Workspace: t.TempDir(), OutDir: t.TempDir(), Seconds: 1},
		Targets:    targets,
		Concurrent: 2, Multiplier: 1,
		// Already past: nothing may start.
		Deadline: time.Now().Add(-time.Second),
		OnStart:  func(string, int) { atomic.AddInt64(&started, 1) },
	})
	if n := atomic.LoadInt64(&started); n != 0 {
		t.Errorf("%d slice(s) started past the deadline", n)
	}
}

// The tuned budget is multiplied into a soak slice, which is the soak's
// substitute for capping a corpus.
func TestSoakMultipliesTheTunedBudget(t *testing.T) {
	b := Budgets{"w": {"slow_fuzzer": 100}}
	if got := b.For("w", "slow_fuzzer", 90) * 20; got != 2000 {
		t.Errorf("slice = %d, want 2000 (tuned 100 x mult 20)", got)
	}
	if got := b.For("w", "other_fuzzer", 90) * 20; got != 1800 {
		t.Errorf("slice = %d, want 1800 (default 90 x mult 20)", got)
	}
}

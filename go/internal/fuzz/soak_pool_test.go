package fuzz

import (
	"context"
	"sync"
	"testing"
	"time"
)

// A SOAK CYCLES UNTIL THE DEADLINE; it does not make one pass and exit.
//
// The loop was `for _, t := range r.Targets`, so every target got exactly one
// slice and the function returned -- while its own doc said "runs a rolling
// pool of targets until the deadline". `soak -hours 10` launched 23 targets,
// waited for the longest, and exited after about an hour.
//
// runOne is stubbed here: this exercises the SCHEDULE, which is the part that
// was wrong. Running real containers is not something a unit test can do.
func TestSoakCyclesUntilTheDeadline(t *testing.T) {
	var mu sync.Mutex
	runs := map[string]int{}

	stub := func(target string) {
		mu.Lock()
		runs[target]++
		mu.Unlock()
		time.Sleep(15 * time.Millisecond)
	}

	targets := []string{"a", "b", "c"}
	deadline := time.Now().Add(220 * time.Millisecond)
	sched := schedule(context.Background(), targets, 2, deadline, stub)

	total := 0
	for _, n := range runs {
		total += n
	}
	if total <= len(targets) {
		t.Errorf("%d slices over %d targets -- that is one pass, not a pool", total, len(targets))
	}
	for _, tg := range targets {
		if runs[tg] == 0 {
			t.Errorf("target %q never ran", tg)
		}
	}
	if sched > 0 && time.Now().Before(deadline) {
		t.Error("returned before the deadline with work left")
	}
}

// THE SAME TARGET IS NEVER IN FLIGHT TWICE. Two slices of one target share a
// corpus directory and a log name; the shell tracked this explicitly.
func TestSoakNeverRunsATargetTwiceAtOnce(t *testing.T) {
	var mu sync.Mutex
	inFlight := map[string]bool{}
	var clash bool

	stub := func(target string) {
		mu.Lock()
		if inFlight[target] {
			clash = true
		}
		inFlight[target] = true
		mu.Unlock()
		time.Sleep(10 * time.Millisecond)
		mu.Lock()
		delete(inFlight, target)
		mu.Unlock()
	}

	schedule(context.Background(), []string{"a", "b"}, 8, // pool wider than the list
		time.Now().Add(150*time.Millisecond), stub)

	if clash {
		t.Error("a target was in flight twice at once")
	}
}

// A cancelled context stops the pool without waiting for the deadline.
func TestSoakStopsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(30 * time.Millisecond); cancel() }()

	done := make(chan struct{})
	go func() {
		schedule(ctx, []string{"a", "b"}, 2, time.Now().Add(10*time.Second),
			func(string) { time.Sleep(10 * time.Millisecond) })
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("the pool ignored a cancelled context")
	}
}

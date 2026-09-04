package fuzz

import (
	"context"
	"sync"
	"time"
)

// SOAK IS THE OTHER MODE, and it is not a longer sweep.
//
// A sweep gives every target the same short slice in a fixed order. A soak
// keeps a POOL of targets in flight and refills it as each finishes, with
// slices long enough that corpus replay is a rounding error rather than the
// whole slice.
//
// WHY LONG SLICES INSTEAD OF CAPPING. libFuzzer never checks -max_total_time
// during seed replay -- ReadAndExecuteSeedCorpora loops the corpus with no
// time or graceful-exit check at all -- so under a 90-second round a corpus
// that takes 800 seconds to replay locks its target out permanently. Under a
// 30-minute slice the same corpus is paid once and leaves most of the slice to
// fuzz. Capping buys headroom the slice already has, and that mistake has been
// made: protocol_fuzzer was cut from 128,650 inputs to 2,000 on the belief it
// was replay-bound, when it replays at ~36,000/s and was actually deadlocked
// on a leaked LWLock.
//
// SO A SOAK DELIBERATELY DOES NOT CAP. It shares corpora, gates and series
// with the sweep; it is a different schedule over the same things.

// SoakRequest is one workspace's soak.
type SoakRequest struct {
	Request
	Targets []string
	// Concurrent targets in flight. Sixteen was measured, with Jobs 1: more
	// jobs makes libFuzzer fork, and a forked worker writes its stats into
	// fuzz-<i>.log rather than onto stdout where the durable log captures it.
	Concurrent int
	// Budgets is the tuned per-target table; Seconds in Request is the
	// fallback, and Multiplier turns a round budget into a soak slice.
	Budgets    Budgets
	Multiplier int
	Deadline   time.Time
	OnStart    func(target string, inFlight int)
	OnDone     func(target string, r Result, err error)
}

// Soak runs a rolling pool of targets until the deadline.
//
// THE DEADLINE STOPS AT A SLICE BOUNDARY, not mid-slice. A soak slice is long
// and mostly useful work; cutting one in half to honour a clock throws away
// the replay it already paid for. A sweep cuts, because its slices are short
// and its promise is about when the machine is free.
func Soak(ctx context.Context, r SoakRequest) []Result {
	conc := r.Concurrent
	if conc < 1 {
		conc = 1
	}
	mult := r.Multiplier
	if mult < 1 {
		mult = 1
	}

	var (
		mu  sync.Mutex
		out []Result
	)

	schedule(ctx, r.Targets, conc, r.Deadline, func(target string) {
		mu.Lock()
		live := len(out) // only for the in-flight display
		mu.Unlock()
		if r.OnStart != nil {
			r.OnStart(target, live)
		}

		req := r.Request
		req.Target = target
		req.Seconds = r.Budgets.For(r.Name, target, r.Request.Seconds) * mult

		res, err := Run(ctx, req)
		mu.Lock()
		if err == nil {
			out = append(out, res)
		}
		mu.Unlock()
		if r.OnDone != nil {
			r.OnDone(target, res, err)
		}
	})
	return out
}

// schedule runs a ROLLING POOL over targets until the deadline.
//
// Factored out of Soak so the schedule can be tested without containers: the
// schedule is what was wrong. It was `for _, t := range targets` -- one slice
// each, then return -- under a doc comment describing the shell's rolling
// pool. `soak -hours 10` therefore fuzzed for about one.
//
// THE DEADLINE IS CHECKED BETWEEN SLICES, NEVER MID-SLICE. A soak slice is
// long and mostly useful work; cutting one in half throws away the corpus
// replay it has already paid for. A sweep cuts because its slices are short.
//
// Returns how many slices it started.
func schedule(ctx context.Context, targets []string, conc int,
	deadline time.Time, run func(target string)) int {

	if len(targets) == 0 {
		return 0
	}
	// A pool wider than the target list is meaningless, and capping is what
	// lets a free slot imply a free target below.
	if conc > len(targets) {
		conc = len(targets)
	}
	if conc < 1 {
		conc = 1
	}

	var (
		mu       sync.Mutex
		wg       sync.WaitGroup
		sem      = make(chan struct{}, conc)
		inFlight = map[string]bool{}
		next     int
		started  int
	)
	past := func() bool { return !deadline.IsZero() && time.Now().After(deadline) }

outer:
	for {
		if ctx.Err() != nil || past() {
			break
		}
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			break outer
		}
		// Re-checked after waiting, which may have taken a whole slice.
		if past() || ctx.Err() != nil {
			<-sem
			break
		}

		mu.Lock()
		picked := ""
		for k := 0; k < len(targets); k++ {
			c := targets[(next+k)%len(targets)]
			if !inFlight[c] {
				picked, next = c, (next+k+1)%len(targets)
				inFlight[c] = true
				break
			}
		}
		if picked != "" {
			started++
		}
		mu.Unlock()

		if picked == "" {
			<-sem
			break
		}
		wg.Add(1)
		go func(target string) {
			defer wg.Done()
			defer func() { <-sem }()
			run(target)
			mu.Lock()
			delete(inFlight, target)
			mu.Unlock()
		}(picked)
	}
	wg.Wait()
	return started
}

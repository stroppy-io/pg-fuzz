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
		mu   sync.Mutex
		out  []Result
		wg   sync.WaitGroup
		sem  = make(chan struct{}, conc)
		live int
	)

	for _, t := range r.Targets {
		if ctx.Err() != nil {
			break
		}
		// Checked BEFORE starting, never during: see the note above.
		if !r.Deadline.IsZero() && time.Now().After(r.Deadline) {
			break
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(target string) {
			defer wg.Done()
			defer func() { <-sem }()

			mu.Lock()
			live++
			n := live
			mu.Unlock()
			if r.OnStart != nil {
				r.OnStart(target, n)
			}

			req := r.Request
			req.Target = target
			req.Seconds = r.Budgets.For(r.Name, target, r.Request.Seconds) * mult

			res, err := Run(ctx, req)
			mu.Lock()
			live--
			if err == nil {
				out = append(out, res)
			}
			mu.Unlock()
			if r.OnDone != nil {
				r.OnDone(target, res, err)
			}
		}(t)
	}
	wg.Wait()
	return out
}

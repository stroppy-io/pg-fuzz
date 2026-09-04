package fuzz

import (
	"context"
	"testing"
)

// A FAILURE IN ONE TARGET MUST NEVER END THE SWEEP.
//
// Sweep returned on the first error, so a failed log create, or one binary
// that lost its exec bit, cost every remaining target its round -- and the
// caller then returned 2 without printing the summary for the targets that had
// run. The shell ran each target in a subshell and recorded "FAILED TO RUN" as
// one line among the results.
func TestSweepCarriesOnPastOneBadTarget(t *testing.T) {
	// "no such target" is the cheapest real failure: Run checks the binary
	// before it touches docker, so this exercises the loop without a daemon.
	sr := SweepRequest{
		Request: Request{OutDir: t.TempDir(), Workspace: t.TempDir(), Name: "ws"},
		Targets: []string{"missing_a_fuzzer", "missing_b_fuzzer", "missing_c_fuzzer"},
	}
	out, err := Sweep(context.Background(), sr)
	if err != nil {
		t.Fatalf("the sweep aborted: %v", err)
	}
	if len(out) != 3 {
		t.Fatalf("got %d results, want one per target even though all failed", len(out))
	}
	for i, r := range out {
		if r.Err == nil {
			t.Errorf("result %d has no error recorded", i)
		}
		if r.Target == "" {
			t.Errorf("result %d does not say which target it belongs to", i)
		}
	}
}

// A CANCELLED CONTEXT IS DIFFERENT and still stops everything: that is the
// operator, not the target.
func TestSweepStopsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := Sweep(ctx, SweepRequest{
		Request: Request{OutDir: t.TempDir(), Workspace: t.TempDir(), Name: "ws"},
		Targets: []string{"a_fuzzer", "b_fuzzer"},
	})
	if err == nil {
		t.Error("a cancelled sweep reported success")
	}
}

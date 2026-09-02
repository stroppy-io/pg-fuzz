package ratchet

import (
	"os"
	"path/filepath"
	"testing"
)

func base() Baseline {
	return Baseline{
		Tolerance: 0.1,
		Floors:    map[string]map[string]int{"ws": {"a": 100000, "b": 200}},
		// BOTH targets carry a regime. A floor with none is legacy and is
		// skipped by design, so a fixture that leaves one out is not testing
		// the tolerance -- it is testing the legacy rule by accident, and it
		// passes for the wrong reason.
		Regimes: map[string]map[string]string{"ws": {"a": "jobs=4", "b": "jobs=1"}},
	}
}

func TestATenthOfTheRecordPasses(t *testing.T) {
	// The tolerance exists so noise does not fail honest runs; it still has to
	// catch the collapse it was written for.
	r := Check(base(), "ws", []Observation{{Target: "b", Execs: 20, Regime: "jobs=1"}}, nil)
	if r.Failed() {
		t.Error("20 against a floor of 200 is exactly the tolerance and must pass")
	}
	r = Check(base(), "ws", []Observation{{Target: "b", Execs: 19, Regime: "jobs=1"}}, nil)
	if !r.Failed() {
		t.Error("19 against a floor of 200 is below tolerance and must fail")
	}
}

func TestADifferentRegimeIsSkippedNotFailed(t *testing.T) {
	// A floor earned at four jobs says nothing about a run at one. Failing it
	// teaches everyone to ignore the gate.
	r := Check(base(), "ws", []Observation{{Target: "a", Execs: 5, Regime: "jobs=1"}}, nil)
	if r.Failed() {
		t.Error("a floor from another regime must not fail the run")
	}
	if r.Judged[0].Outcome != Incomparable {
		t.Errorf("outcome = %v, want Incomparable -- and it must be SAID, not silently passed",
			r.Judged[0].Outcome)
	}
}

func TestNoBaselineIsNotAPass(t *testing.T) {
	// A floor cannot be regressed from before it exists, and reporting that as
	// success makes a workspace with no history look identical to a healthy one.
	r := Check(Baseline{Tolerance: 0.1}, "ws", []Observation{{Target: "a", Execs: 1}}, nil)
	if !r.Seeded {
		t.Error("an absent baseline must be reported as unseeded")
	}
}

func TestAcknowledgedRegressionDoesNotFail(t *testing.T) {
	acks := map[string]string{"b": "known: replay eats the slice, see T-whatever"}
	r := Check(base(), "ws", []Observation{{Target: "b", Execs: 1, Regime: "jobs=1"}}, acks)
	if r.Failed() {
		t.Error("an acknowledged regression must not fail the round")
	}
	if r.Judged[0].Outcome != Acknowledged || r.Judged[0].Note == "" {
		t.Error("the acknowledgement and its reason must both survive")
	}
}

func TestFloorsOnlyGoUp(t *testing.T) {
	b := base()
	b.Update("ws", []Observation{{Target: "b", Execs: 50, Regime: "jobs=1"}})
	if got := b.Floors["ws"]["b"]; got != 200 {
		t.Errorf("floor moved down to %d; a ratchet that lowers is not one", got)
	}
	b.Update("ws", []Observation{{Target: "b", Execs: 900, Regime: "jobs=1", Rate: 3.0}})
	if got := b.Floors["ws"]["b"]; got != 900 {
		t.Errorf("floor = %d, want 900", got)
	}
	if b.Regimes["ws"]["b"] != "jobs=1" {
		t.Error("a new floor must carry the regime that earned it")
	}
}

// Against the real baseline: 34 workspaces of floors have to survive a
// round trip, or the port silently drops somebody's history.
func TestRealBaselineRoundTrips(t *testing.T) {
	p := filepath.Join(os.Getenv("HOME"), "Projects/fuzzing/pg-fuzz/scripts/ratchet-baseline.json")
	b, err := Load(p)
	if err != nil {
		t.Skip("no baseline here")
	}
	if len(b.Floors) == 0 {
		t.Fatal("baseline parsed with no floors")
	}
	var targets int
	for _, m := range b.Floors {
		targets += len(m)
	}
	t.Logf("%d workspaces, %d floors, tolerance %.2f, %d regime maps",
		len(b.Floors), targets, b.Tolerance, len(b.Regimes))

	out := filepath.Join(t.TempDir(), "b.json")
	if err := b.Save(out); err != nil {
		t.Fatal(err)
	}
	again, err := Load(out)
	if err != nil {
		t.Fatal(err)
	}
	var targets2 int
	for _, m := range again.Floors {
		targets2 += len(m)
	}
	if targets2 != targets {
		t.Errorf("round trip lost floors: %d -> %d", targets, targets2)
	}
	if len(again.Regimes) != len(b.Regimes) {
		t.Errorf("round trip lost regimes: %d -> %d", len(b.Regimes), len(again.Regimes))
	}
}

// A floor with NO recorded regime is legacy: earned before regimes were
// tracked, across a mix of job counts and budgets, so it is not known to be
// comparable to anything.
//
// Treating it as comparable is what produced 7 of 22 targets sitting below a
// tenth of their floor while fuzzing perfectly well.
func TestALegacyFloorIsSkippedNotJudged(t *testing.T) {
	b := Baseline{
		Tolerance: 0.1,
		Floors:    map[string]map[string]int{"ws": {"legacy": 200}},
		Regimes:   map[string]map[string]string{"ws": {}}, // nothing recorded
	}
	// Far below the floor: if this were judged it would fail.
	r := Check(b, "ws", []Observation{{Target: "legacy", Execs: 1, Regime: "jobs=4"}}, nil)
	if r.Failed() {
		t.Error("a floor with no recorded regime must be skipped, not failed")
	}
	if len(r.Judged) != 1 || r.Judged[0].Outcome != Incomparable {
		t.Errorf("expected the target to be reported incomparable, got %+v", r.Judged)
	}
	if r.Judged[0].Earned != "" {
		t.Errorf("a legacy floor has no earned regime; got %q", r.Judged[0].Earned)
	}
}

// A RATE floor survives a regime change; an EXECUTION floor does not.
//
// Per-worker-second throughput is independent of budget and job count, so a
// rate floor stays comparable when the job count changes. An earlier version
// skipped the whole target on a regime mismatch and threw the rate floor away
// with the exec floor -- which let pg17-ext-all-und pass at 8.5% of a rate
// floor it had already achieved.
func TestARateFloorSurvivesARegimeChange(t *testing.T) {
	b := Baseline{
		Tolerance:  0.1,
		Floors:     map[string]map[string]int{"ws": {"binary_recv_fuzzer": 2899981}},
		Regimes:    map[string]map[string]string{"ws": {"binary_recv_fuzzer": "jobs=1"}},
		RateFloors: map[string]map[string]Rate{"ws": {"binary_recv_fuzzer": 16860}},
	}
	o := Observation{Target: "binary_recv_fuzzer", Execs: 5_000_000,
		Rate: 1439.04, Regime: "jobs=16"}

	r := Check(b, "ws", []Observation{o}, nil)
	if !r.Failed() {
		t.Fatal("8.5% of a comparable rate floor must fail even though the exec floor is not comparable")
	}
	j := r.Judged[0]
	if !j.ByRate {
		t.Error("the verdict must say it was decided by the rate floor")
	}
	if !j.ExecFloorSkipped {
		t.Error("the exec floor was earned at jobs=1 and judged at jobs=16; that has to be reported")
	}
}

// The regime comes from the LOG, and the exec floor is only compared within it.
func TestAnExecFloorAloneIsSkippedAcrossRegimes(t *testing.T) {
	b := Baseline{
		Tolerance: 0.1,
		Floors:    map[string]map[string]int{"ws": {"t": 1000}},
		Regimes:   map[string]map[string]string{"ws": {"t": "jobs=1"}},
	}
	r := Check(b, "ws", []Observation{{Target: "t", Execs: 1, Regime: "jobs=16"}}, nil)
	if r.Failed() {
		t.Error("no comparable floor exists; this must be skipped, not failed")
	}
	if r.Judged[0].Outcome != Incomparable {
		t.Errorf("expected Incomparable, got %v", r.Judged[0].Outcome)
	}
}

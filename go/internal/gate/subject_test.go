package gate

import (
	"testing"

	"pgfuzz/internal/logs"
)

// A BROKEN HARNESS AND AN INTERESTING RESULT ARE NOT THE SAME EVENT.
//
// Every gate used to fail the round identically, so a UB site in PostgreSQL
// and a target that executed nothing produced the same red. That is how a
// board stops being read -- and the starvation gate, the one that catches the
// harness silently doing no work, is then the first casualty.
//
// Harness is the ZERO VALUE on purpose: a gate added later and never
// classified defaults to "stop and fix this", which is the safe direction to
// be wrong in.
func TestVerdictSubject(t *testing.T) {
	// A target that executed almost nothing: the machinery is not working.
	starved := Starvation(logs.Stats{Target: "regex_fuzzer", Execs: 3}, 10_000, nil)
	if !starved.Failed {
		t.Fatal("3 executions against a floor of 10,000 should fail")
	}
	if starved.About != Harness {
		t.Fatalf("starvation is a harness failure, got %v", starved.About)
	}

	// A round that did not sweep every built target: also the machinery.
	incomplete := RoundComplete([]string{"a_fuzzer"}, []string{"a_fuzzer", "b_fuzzer"})
	if !incomplete.Failed {
		t.Fatal("a round missing a built target should fail")
	}
	if incomplete.About != Harness {
		t.Fatalf("round-complete is a harness failure, got %v", incomplete.About)
	}

	// A UB site outside its accepted scope: the fuzzer found something.
	ub := UBSan(logs.Stats{
		Target: "datetime_fuzzer",
		UB: []logs.UBSite{{
			Function: "date2j", File: "datetime.c", Line: 305,
			Class: "signed-overflow",
			Text:  "signed integer overflow: 9714499 * 365 cannot be represented in type 'int'",
		}},
	}, "ci-rel_16_stable-undefined", nil)
	if !ub.Failed {
		t.Fatal("an unaccepted UB site should fail")
	}
	if ub.About != Finding {
		t.Fatalf("ubsan is a finding, not a harness failure, got %v", ub.About)
	}

	if Harness.String() != "harness" || Finding.String() != "finding" {
		t.Fatal("a subject must name itself")
	}
}

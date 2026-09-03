package gate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"pgfuzz/internal/logs"
)

func TestSilenceIsNotAPass(t *testing.T) {
	// A log that yielded nothing says nothing about the run. Treating that as
	// health is how four dead targets survived a whole campaign.
	if v := Starvation(logs.Stats{Target: "x"}, 10000, nil); !v.Failed {
		t.Error("an empty log must fail the gate, not pass it")
	}
}

func TestSlowUnitsUsesTheConfiguredTimeout(t *testing.T) {
	// The finding is that configured and observed disagree; hardcoding one
	// side hides it.
	if v := SlowUnits(logs.Stats{Target: "x", SlowestUnit: 27, Timeout: 25}); !v.Failed {
		t.Error("27s against -timeout=25 must fail")
	}
	if v := SlowUnits(logs.Stats{Target: "x", SlowestUnit: 27, Timeout: 60}); v.Failed {
		t.Error("27s against -timeout=60 must not fail")
	}
}

func TestRoundCompleteNamesWhatNeverRan(t *testing.T) {
	v := RoundComplete([]string{"a", "b"}, []string{"a", "b", "c"})
	if !v.Failed {
		t.Fatal("a short round must fail")
	}
	if len(v.Detail) == 0 || !contains(v.Detail[0], "c") {
		t.Errorf("the missing target must be named: %v", v.Detail)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}

// Against the real accept-list and the real logs.
func TestUBSanAgainstTheRealBaseline(t *testing.T) {
	base := filepath.Join(os.Getenv("HOME"), "Projects/fuzzing/pg-fuzz/scripts/ubsan-baseline.tsv")
	acc, err := LoadAccepted(base)
	if err != nil {
		t.Skip("no baseline on this machine")
	}
	if len(acc) == 0 {
		t.Fatal("baseline parsed as empty")
	}
	t.Logf("%d accepted sites", len(acc))

	hits, _ := filepath.Glob(filepath.Join(os.Getenv("HOME"), "pgfuzz", "*-und", "soak-*_fuzzer.log"))
	unaccepted := map[string]bool{}
	for _, h := range hits {
		s, err := logs.ParseFile(h)
		if err != nil {
			continue
		}
		ws := filepath.Base(filepath.Dir(h))
		if v := UBSan(s, ws, acc); v.Failed {
			for _, d := range v.Detail {
				unaccepted[d] = true
			}
		}
	}
	for d := range unaccepted {
		t.Logf("UNACCEPTED: %s", d)
	}
	t.Logf("%d logs, %d distinct unaccepted sites", len(hits), len(unaccepted))
}

// A starvation floor nobody can acknowledge is a floor people learn to
// ignore. The shell's gate honoured known-starved.tsv; the Go port had no
// parameter for it at all, so a target with a written-down reason failed the
// round every round.
func TestStarvationHonoursAcknowledgements(t *testing.T) {
	st := logs.Stats{Target: "numeric_fuzzer", Execs: 100, Done: 100, Inited: 1}

	if v := Starvation(st, 100000, nil); !v.Failed {
		t.Fatal("a target far below its floor must fail when unacknowledged")
	}

	acks := map[string]string{
		"numeric_fuzzer": "numeric_fuzzer\tstarved upstream\tFINDINGS/x\t2026-09-01",
	}
	v := Starvation(st, 100000, acks)
	if v.Failed {
		t.Error("an acknowledged target must not fail the round")
	}
	if !strings.Contains(strings.Join(v.Detail, " "), "starved upstream") {
		t.Errorf("the reason must travel with the verdict, got %v", v.Detail)
	}
}

// An acknowledgement is still honoured when it goes stale -- silently
// un-suppressing a target is how a gate starts crying wolf -- but the age is
// reported, because a cause that was true a month ago may be fixed.
func TestStaleAcknowledgementIsReportedNotWithdrawn(t *testing.T) {
	st := logs.Stats{Target: "numeric_fuzzer", Execs: 100, Done: 100, Inited: 1}
	old := time.Now().Add(-60 * 24 * time.Hour).Format("2006-01-02")
	acks := map[string]string{
		"numeric_fuzzer": "numeric_fuzzer\tstarved upstream\tFINDINGS/x\t" + old,
	}
	v := Starvation(st, 100000, acks)
	if v.Failed {
		t.Error("a stale acknowledgement must still suppress the failure")
	}
	if !strings.Contains(strings.Join(v.Detail, " "), "days old") {
		t.Errorf("a stale acknowledgement must be reported, got %v", v.Detail)
	}
}

// The fleet-level gate. It was written because 41 of 46 slices recorded no
// final stats at all and nothing noticed: libFuzzer's per-job logs collide
// under -jobs, so a parent log can come back with no totals while every
// target looks individually unremarkable. A floor cannot be verified against
// a slice that never said what it did.
func TestFinalStatsFailsARoundThatWentMostlySilent(t *testing.T) {
	loud := func(n string) logs.Stats { return logs.Stats{Target: n, Execs: 1000, Done: 1000, Inited: 10} }
	mute := func(n string) logs.Stats { return logs.Stats{Target: n} }

	all := []logs.Stats{loud("a"), loud("b"), loud("c"), loud("d")}
	if v := FinalStats(all, 90); v.Failed {
		t.Errorf("a fully-reporting round failed: %v", v.Detail)
	}

	mostly := []logs.Stats{loud("a"), mute("b"), mute("c"), mute("d")}
	v := FinalStats(mostly, 90)
	if !v.Failed {
		t.Fatal("a round where 3 of 4 slices reported nothing must fail")
	}
	joined := strings.Join(v.Detail, " ")
	for _, want := range []string{"1 of 4", "25%", "b", "c", "d"} {
		if !strings.Contains(joined, want) {
			t.Errorf("verdict does not name %q: %s", want, joined)
		}
	}
}

// A target that executed nothing is starvation's verdict, not this one.
// Reporting the same slice twice under two names makes a round look worse
// than it is.
func TestFinalStatsDoesNotDoubleCountStarvation(t *testing.T) {
	// Execs 0 but the log clearly spoke: it INITED and reported a Done line.
	ran := logs.Stats{Target: "a", Inited: 500, Done: 500}
	if v := FinalStats([]logs.Stats{ran}, 90); v.Failed {
		t.Errorf("a slice that reported its counts was called silent: %v", v.Detail)
	}
}

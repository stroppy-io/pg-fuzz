package gate

import (
	"os"
	"path/filepath"
	"testing"

	"pgfuzz/internal/logs"
)

func TestSilenceIsNotAPass(t *testing.T) {
	// A log that yielded nothing says nothing about the run. Treating that as
	// health is how four dead targets survived a whole campaign.
	if v := Starvation(logs.Stats{Target: "x"}, 10000); !v.Failed {
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

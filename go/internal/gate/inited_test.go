package gate

import (
	"strings"
	"testing"

	"pgfuzz/internal/logs"
)

// SILENCE IS A FAILURE, AND THERE ARE THREE OF THEM.
//
// A target with no executions and no completed replay fails -- treating
// silence as health is how four dead targets survived a whole campaign. But
// all three silences failed with one message that named none of them: died
// before libFuzzer started (look at the harness initialiser), started and
// never fuzzed (look at the corpus or the target), and no evidence either way
// (look at the log). logs.Startup has separated them since it was written, and
// the person reading the failure still had to open the log.
func TestSilentTargetSaysWhichSilence(t *testing.T) {
	for _, c := range []struct {
		name  string
		stats logs.Stats
		want  string
	}{
		{"died", logs.Stats{Target: "t", Aborted: true},
			"died before libFuzzer started"},
		{"inited", logs.Stats{Target: "t", Inited: 4096, Banner: true},
			"started but never fuzzed"},
		{"nothing", logs.Stats{Target: "t"},
			"no evidence either way"},
	} {
		v := Starvation(c.stats, 0, nil)
		if !v.Failed {
			t.Errorf("%s: a silent target passed the gate", c.name)
		}
		if got := strings.Join(v.Detail, "\n"); !strings.Contains(got, c.want) {
			t.Errorf("%s: detail %q does not say %q", c.name, got, c.want)
		}
	}
}

// A target that fuzzed passes, or the gate fails everything.
func TestFuzzedPasses(t *testing.T) {
	s := logs.Stats{Target: "t", Inited: 100, Done: 5000,
		Execs: 1_000_000, NewUnits: 42, Banner: true}
	if v := Starvation(s, 0, nil); v.Failed {
		t.Errorf("a healthy slice failed: %v", v.Detail)
	}
}

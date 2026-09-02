package logs

import (
	"os"
	"path/filepath"
	"testing"
)

// Parse against the real logs on this machine, because a parser tested only on
// hand-written samples matches the samples.
func TestParsesRealRunLogs(t *testing.T) {
	ws := os.Getenv("PGFUZZ_WS")
	if ws == "" {
		ws = filepath.Join(os.Getenv("HOME"), "pgfuzz")
	}
	hits, _ := filepath.Glob(filepath.Join(ws, "*", "soak-*_fuzzer.log"))
	if len(hits) == 0 {
		t.Skip("no run logs on this machine")
	}
	if len(hits) > 12 {
		hits = hits[:12]
	}
	var withExecs, withCov, withUB int
	for _, h := range hits {
		s, err := ParseFile(h)
		if err != nil {
			t.Fatal(err)
		}
		if s.Execs > 0 {
			withExecs++
		}
		if s.Cov > 0 {
			withCov++
		}
		if len(s.UB) > 0 {
			withUB++
		}
	}
	if withExecs == 0 {
		t.Error("no log yielded an execution count; the parser is not reading these")
	}
	t.Logf("%d logs: %d with execs, %d with coverage, %d with UB reports",
		len(hits), withExecs, withCov, withUB)
}

func TestReplayOnlyNeedsBothNumbers(t *testing.T) {
	// The failure this catches reports a LARGE execution count, which is why
	// it went unseen: replaying 100k inputs looks like the busiest target.
	if !(Stats{Inited: 100000, Done: 100050, NewUnits: 0}).ReplayOnly() {
		t.Error("a slice that added nothing after replay should be flagged")
	}
	if (Stats{Inited: 100, Done: 900000, NewUnits: 4000}).ReplayOnly() {
		t.Error("a productive slice must not be flagged")
	}
	if (Stats{}).ReplayOnly() {
		t.Error("an unparsed log must not be flagged; absence is not evidence")
	}
}

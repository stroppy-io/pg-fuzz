package gate

import (
	"path/filepath"
	"strings"
	"testing"
)

func seriesWith(t *testing.T, ws string, rounds [][]string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "ubsan-series.jsonl")
	for _, sites := range rounds {
		if err := RecordUBSanRound(p, UBSanRound{WS: ws, Log: "r.log", Sites: sites}); err != nil {
			t.Fatal(err)
		}
	}
	return p
}

// A row quiet for three informative rounds is withdrawable. One quiet round is
// not evidence: a fuzzer reaches a site only if it happens to generate an
// input that does.
func TestWithdrawableAfterThreeQuietRounds(t *testing.T) {
	// Three rounds where "other" fired and "old_site" did not; this round
	// makes the third absence.
	p := seriesWith(t, "w1", [][]string{{"other"}, {"other"}})
	v := UBSanWithdrawals(p, "w1", []string{"old_site", "other"}, []string{"other"})
	joined := strings.Join(v.Detail, " ")
	if !strings.Contains(joined, "withdrawable: old_site") {
		t.Errorf("a row quiet for 3 informative rounds was not offered for removal: %s", joined)
	}
}

func TestOneQuietRoundIsReportedNotWithdrawn(t *testing.T) {
	p := seriesWith(t, "w1", [][]string{{"old_site", "other"}})
	v := UBSanWithdrawals(p, "w1", []string{"old_site", "other"}, []string{"other"})
	joined := strings.Join(v.Detail, " ")
	if strings.Contains(joined, "withdrawable") {
		t.Errorf("one quiet round must not retire a row: %s", joined)
	}
	if !strings.Contains(joined, "quiet (1/3)") {
		t.Errorf("a quiet round should be reported as progress: %s", joined)
	}
}

// A round that observed nothing is the shape of BOTH "all fixed" and
// "detection is off". Counting it as absence would let a broken build retire
// the whole list.
func TestUninformativeRoundsDoNotCountAsAbsence(t *testing.T) {
	// Two rounds that saw nothing at all, then a real one where old_site fired.
	p := seriesWith(t, "w1", [][]string{{}, {}, {"old_site"}})
	if n := AbsentStreak(p, "w1", "old_site"); n != 0 {
		t.Errorf("absent streak = %d, want 0 -- empty rounds are not evidence", n)
	}
}

// Everything going quiet at once is the alarm, not the good news.
func TestEverythingQuietAtOnceIsReportedAsDetectionOff(t *testing.T) {
	p := seriesWith(t, "w1", [][]string{{"a", "b", "c"}})
	v := UBSanWithdrawals(p, "w1", []string{"a", "b", "c"}, nil)
	joined := strings.Join(v.Detail, " ")
	if !strings.Contains(joined, "detection being OFF") {
		t.Errorf("a total blackout must be called out: %s", joined)
	}
	if strings.Contains(joined, "withdrawable") {
		t.Error("a total blackout must not offer to retire the whole list")
	}
}

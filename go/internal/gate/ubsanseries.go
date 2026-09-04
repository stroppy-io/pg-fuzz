package gate

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

// THE ACCEPT-LIST HAS TO BE ABLE TO SHRINK.
//
// A gate that only ever grows its list of accepted findings becomes the table
// nobody reads, which is the thing the accept-list was introduced to replace.
// The port kept the half that judges what fired and dropped the half that
// retires a row, so a site fixed upstream stayed accepted forever and nothing
// ever suggested removing it.
//
// The judgement cannot be made from one round. A fuzzer reaches a site only if
// it happens to generate an input that does, so a quiet round is the norm
// rather than news -- absence has to be counted over a series, and only over
// rounds that saw SOMETHING.
//
// A ROUND THAT OBSERVED NOTHING IS NOT EVIDENCE, and this is the trap the
// series exists to avoid. "Every accepted row went quiet" is the shape of both
// "they were all fixed" and "detection is off" -- and the second is a real
// hazard here, because build.sh makes signed-integer-overflow recoverable and
// stripping one flag too many turns detection off while every gate reports
// clean. Counting an uninformative round as absence would let a broken build
// retire the entire list.

// WithdrawRounds is how many consecutive informative rounds a site must be
// absent from before its row is called withdrawable. One is not evidence.
const WithdrawRounds = 3

// UBSanRound is what one round saw, appended to the series.
type UBSanRound struct {
	WS  string `json:"ws"`
	Log string `json:"log"`
	// Informative is false when the round saw no accepted site at all. Such a
	// round contributes no evidence in either direction.
	Informative bool     `json:"informative"`
	Sites       []string `json:"sites"`
}

// RecordUBSanRound appends what this round observed.
func RecordUBSanRound(path string, r UBSanRound) error {
	sort.Strings(r.Sites)
	r.Informative = len(r.Sites) > 0
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(append(b, '\n'))
	return err
}

// AbsentStreak counts consecutive informative rounds, newest first, in which
// the token did not fire. The current round is included by the caller.
func AbsentStreak(path, ws, token string) int {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	var rounds []UBSanRound
	for _, line := range strings.Split(string(b), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var r UBSanRound
		if json.Unmarshal([]byte(line), &r) != nil {
			continue
		}
		if r.WS == ws && r.Informative {
			rounds = append(rounds, r)
		}
	}
	streak := 0
	for i := len(rounds) - 1; i >= 0; i-- {
		fired := false
		for _, s := range rounds[i].Sites {
			if s == token {
				fired = true
				break
			}
		}
		if fired {
			break
		}
		streak++
	}
	return streak
}

// UBSanWithdrawals reports rows that have been quiet long enough to remove,
// and the one case that must never be read as good news.
//
// accepted is every token the accept-list holds for this workspace; seen is
// what this round actually observed.
func UBSanWithdrawals(seriesPath, ws string, accepted, seen []string) Verdict {
	v := Verdict{Name: "ubsan-withdrawal", About: Finding}
	if len(accepted) == 0 {
		return v
	}
	fired := map[string]bool{}
	for _, s := range seen {
		fired[s] = true
	}

	var quiet, withdrawable []string
	for _, tok := range accepted {
		if fired[tok] {
			continue
		}
		quiet = append(quiet, tok)
		// +1 for this round, which has not been written yet.
		if AbsentStreak(seriesPath, ws, tok)+1 >= WithdrawRounds {
			withdrawable = append(withdrawable, tok)
		}
	}
	sort.Strings(quiet)
	sort.Strings(withdrawable)

	// THE ALARM. Said out loud rather than inferred, because it is the one
	// reading of "everything went quiet" that looks like success.
	if len(accepted) > 1 && len(quiet) == len(accepted) {
		v.Detail = append(v.Detail, fmt.Sprintf(
			"every accepted row (%d) went quiet in one round -- that is more likely "+
				"detection being OFF than %d upstream fixes; check the build kept "+
				"-fsanitize=signed-integer-overflow before deleting anything",
			len(accepted), len(accepted)))
		return v
	}
	for _, tok := range withdrawable {
		v.Detail = append(v.Detail, fmt.Sprintf(
			"withdrawable: %s has not fired in %d informative rounds -- remove its row",
			tok, WithdrawRounds))
	}
	for _, tok := range quiet {
		n := AbsentStreak(seriesPath, ws, tok) + 1
		if n < WithdrawRounds {
			v.Detail = append(v.Detail, fmt.Sprintf(
				"quiet (%d/%d): %s", n, WithdrawRounds, tok))
		}
	}
	return v
}

// InScope reports whether an accepted row applies to this workspace.
//
// Exported so the caller can ask which rows it is judging: withdrawal is a
// question about the rows that COULD have fired here, and counting a row
// scoped to another workspace as quiet would retire it on evidence from a
// build it was never about.
func InScope(a Accepted, ws string) bool {
	if len(a.Scope) == 0 {
		return true
	}
	for _, g := range a.Scope {
		if g == "" || g == "*" || matchGlob(g, ws) {
			return true
		}
	}
	return false
}

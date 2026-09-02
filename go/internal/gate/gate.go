// Package gate holds the checks that fail a round.
//
// Each of these was a separate shell script with its own log parser, which is
// four chances to disagree about whether a target ran. They are pure functions
// over logs.Stats here: the parsing happens once, and a gate is the judgement
// only.
//
// WHY GATES RATHER THAN REPORTS
// =============================
// This project already detected starvation and printed a table. It printed
// that table across campaigns nobody acted on. A number in a report is a
// number somebody has to notice; a gate that fails the round is a fact that
// has to be acknowledged, and an acknowledgement is a commit somebody made.
package gate

import (
	"fmt"
	"strings"
	"time"

	"pgfuzz/internal/logs"
)

// Verdict is one gate's answer.
type Verdict struct {
	Name   string
	Failed bool
	Detail []string
}

func (v Verdict) String() string {
	if !v.Failed {
		return v.Name + ": ok"
	}
	return v.Name + ": FAILED\n  " + strings.Join(v.Detail, "\n  ")
}

// Starvation fails a target that executed almost nothing.
//
// The floor is deliberately blunt. A target that ran 192 inputs when it has
// run 264,893 is not slow, it is broken -- and the two are indistinguishable
// from a report that only prints the number.
// Starvation fails a target that did not really fuzz.
//
// ACKS are a parameter because a floor nobody can acknowledge is a floor
// people learn to ignore. A target below the floor with a written-down reason
// is reported as known and does not fail the round; the reason travels with
// it so the verdict can be argued with rather than merely suppressed. An
// acknowledgement older than StaleAck is still honoured but reported, because
// a cause that was true a month ago may have been fixed since.
func Starvation(s logs.Stats, floor int, acks map[string]string) Verdict {
	v := Verdict{Name: "starvation"}
	if s.Execs == 0 && s.Done == 0 {
		// No numbers at all is not a pass. A log that could not be read says
		// nothing about the run, and treating silence as health is how four
		// dead targets survived a whole campaign.
		v.Failed = true
		v.Detail = append(v.Detail, s.Target+": no executed-unit count in the log")
		return v
	}
	if s.Execs < floor {
		if row, ok := acks[s.Target]; ok {
			v.Detail = append(v.Detail, fmt.Sprintf(
				"%s: %d executions, floor %d -- known: %s",
				s.Target, s.Execs, floor, ackReason(row)))
			if d, ok := ackAge(row); ok && d > StaleAck {
				v.Detail = append(v.Detail, fmt.Sprintf(
					"%s: the acknowledgement is %d days old -- re-check the cause",
					s.Target, int(d.Hours()/24)))
			}
		} else {
			v.Failed = true
			v.Detail = append(v.Detail,
				fmt.Sprintf("%s: %d executions, floor %d", s.Target, s.Execs, floor))
		}
	}
	if s.ReplayOnly() {
		v.Failed = true
		v.Detail = append(v.Detail, fmt.Sprintf(
			"%s: spent the slice on corpus replay -- INITED %d, DONE %d, %d new units",
			s.Target, s.Inited, s.Done, s.NewUnits))
	}
	return v
}

// SlowUnits fails a run whose slowest unit outran the configured timeout.
//
// The timeout comes from the run itself, not a constant: the finding IS that
// the configured and observed values disagree, and hardcoding one side of that
// comparison hides exactly the case worth seeing.
func SlowUnits(s logs.Stats) Verdict {
	v := Verdict{Name: "slow-units"}
	limit := s.Timeout
	if limit == 0 {
		limit = 25
	}
	if s.SlowestUnit > limit {
		v.Failed = true
		v.Detail = append(v.Detail, fmt.Sprintf(
			"%s: slowest unit %ds against -timeout=%d -- the timeout did not fire, "+
				"and the unit was NOT saved because it completed",
			s.Target, s.SlowestUnit, limit))
	}
	return v
}

// Accepted is one row of the UBSan accept-list.
type Accepted struct {
	Function string
	Scope    []string // workspace globs; "*" means everywhere
	Site     string
	Class    string
}

// UBSan fails a UB site nobody has accepted.
//
// Keyed on the FUNCTION, like the baseline: file:line shifts under a minor
// release -- tm2timestamp is timestamp.c:2012 on 17.7 and :2016 on 17.11 --
// and a key that moves with a point upgrade fails open on every branch at
// once.
func UBSan(s logs.Stats, ws string, accepted []Accepted) Verdict {
	v := Verdict{Name: "ubsan"}
	seen := map[string]bool{}
	for _, u := range s.UB {
		if u.Function == "" {
			// Unattributable: the log had a site but no DEDUP_TOKEN. Reported
			// rather than dropped -- an unnameable site is still a site.
			key := u.File + ":" + fmt.Sprint(u.Line)
			if !seen[key] {
				seen[key] = true
				v.Failed = true
				v.Detail = append(v.Detail,
					fmt.Sprintf("unattributed UB at %s (no DEDUP_TOKEN): %s", key, u.Text))
			}
			continue
		}
		if inScope(accepted, u.Function, ws) {
			continue
		}
		if seen[u.Function] {
			continue
		}
		seen[u.Function] = true
		v.Failed = true
		v.Detail = append(v.Detail, fmt.Sprintf(
			"%s at %s:%d (%s) is not in the accept-list: %s",
			u.Function, u.File, u.Line, u.Class, u.Text))
	}
	return v
}

func inScope(accepted []Accepted, fn, ws string) bool {
	for _, a := range accepted {
		if a.Function != fn {
			continue
		}
		for _, g := range a.Scope {
			if g == "*" || matchGlob(g, ws) {
				return true
			}
		}
	}
	return false
}

// matchGlob handles the trailing-* form the baseline uses.
func matchGlob(pat, s string) bool {
	if strings.HasSuffix(pat, "*") {
		return strings.HasPrefix(s, strings.TrimSuffix(pat, "*"))
	}
	return pat == s
}

// RoundComplete fails a round that did not reach every built target.
//
// Against the targets that were BUILT, not a fixed number: workspaces
// legitimately differ -- mysql_fdw is dropped from the address build because
// RTLD_DEEPBIND is incompatible with ASan -- and a constant would fail honest
// workspaces while passing one whose build silently lost a target.
func RoundComplete(swept, built []string) Verdict {
	v := Verdict{Name: "round-complete"}
	have := map[string]bool{}
	for _, t := range swept {
		have[t] = true
	}
	var missing []string
	for _, t := range built {
		if !have[t] {
			missing = append(missing, t)
		}
	}
	if len(missing) > 0 {
		v.Failed = true
		v.Detail = append(v.Detail, fmt.Sprintf(
			"%d of %d targets never ran: %s", len(missing), len(built),
			strings.Join(missing, " ")))
		v.Detail = append(v.Detail,
			"a short round is an untested cell that reads like a clean one")
	}
	return v
}

// StaleAck is how old an acknowledgement may be before it is reported.
//
// Thirty days, the same window the shell used. It does not withdraw the
// acknowledgement -- silently un-suppressing a target is how a gate starts
// crying wolf -- it says the reason is due for review.
const StaleAck = 30 * 24 * time.Hour

// ackReason is the second tab-separated column of a known-starved row:
// target, reason, findings-ref, date.
func ackReason(row string) string {
	f := strings.Split(row, "\t")
	if len(f) >= 2 && strings.TrimSpace(f[1]) != "" {
		return strings.TrimSpace(f[1])
	}
	return "no reason recorded"
}

// ackAge is how long ago the row was acknowledged, from its fourth column.
func ackAge(row string) (time.Duration, bool) {
	f := strings.Split(row, "\t")
	if len(f) < 4 {
		return 0, false
	}
	d, err := time.Parse("2006-01-02", strings.TrimSpace(f[3]))
	if err != nil {
		return 0, false
	}
	return time.Since(d), true
}

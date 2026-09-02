// Package watchdog kills fuzz containers that outlive their own
// -max_total_time.
//
// WHY THIS CANNOT BE DONE INSIDE THE TARGET
// =========================================
// libFuzzer enforces -timeout with SetTimer()/ITIMER_REAL/SIGALRM. PostgreSQL's
// timeout.c owns ITIMER_REAL and SIGALRM too, and InitializeTimeouts() CLEARS
// the registration table -- so inside a PostgreSQL fuzz target the per-input
// timeout silently never fires. protocol_fuzzer sat 23 minutes past a 90-second
// deadline on orafce's dbms_alert.waitany, which blocks on a condition variable
// nothing will ever signal, and the whole growth run stalled behind it.
//
// Three attempts to arm the deadline inside protocol_fuzzer all hit
// Assert(all_timeouts[id].timeout_handler != NULL) and were reverted. A watchdog
// in a different PROCESS cannot be disarmed by any of that, and it catches every
// hang rather than the one we happen to know about.
//
// It kills the CONTAINER, not the target process: the wrapper respawns workers,
// so killing one worker just hands the hang to its replacement.
package watchdog

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Options tunes the loop. The defaults are the ones the campaign ran with.
type Options struct {
	Grace    time.Duration // past -max_total_time before acting
	TermWait time.Duration // how long SIGTERM gets to flush stats
	Interval time.Duration // between sweeps
	Log      io.Writer
	Beat     time.Duration // heartbeat period; 0 disables
	Once     bool          // one sweep, then return -- for tests and for `-n`
}

// A container we might have to act on.
type container struct {
	ID      string
	Name    string
	Started time.Time
	Cmd     string
}

var (
	budgetRe = regexp.MustCompile(`max_total_time=(\d+)`)
	targetRe = regexp.MustCompile(`[a-z_]+_fuzzer`)
)

// Run watches until ctx is done.
func Run(ctx context.Context, o Options) error {
	if o.Grace == 0 {
		o.Grace = 5 * time.Minute
	}
	if o.TermWait == 0 {
		o.TermWait = 20 * time.Second
	}
	if o.Interval == 0 {
		o.Interval = time.Minute
	}
	if o.Beat == 0 {
		o.Beat = time.Hour
	}
	if o.Log == nil {
		o.Log = io.Discard
	}

	say := func(f string, a ...any) {
		// FULL DATE, not just the clock. This log ran for days with HH:MM:SS
		// only, and a filter like `awk '$1 > "14:05"'` then matches every
		// previous day too. That misread historical kills as current twice in
		// one session -- once reporting 40 kills that had all happened the day
		// before, and once reporting 28 immediately after a restart that had
		// produced none. A log used as evidence needs a date.
		fmt.Fprintf(o.Log, "%s %s\n", time.Now().Format("2006-01-02 15:04:05"),
			fmt.Sprintf(f, a...))
	}
	say("start: grace=%s interval=%s", o.Grace, o.Interval)

	lastBeat := time.Now()
	for {
		seen, total, err := sweep(ctx, o, say)
		if err != nil && ctx.Err() != nil {
			return ctx.Err()
		}
		// HEARTBEAT. This log recorded only kills, so "nothing to report" and
		// "silently broken" produced identical output -- and for seventeen
		// hours they were the same thing. A line saying how many containers
		// were examined makes a dead watchdog visible without having to
		// suspect it first.
		if time.Since(lastBeat) >= o.Beat {
			lastBeat = time.Now()
			say("watching: %d fuzz container(s) of %d running", seen, total)
		}
		if o.Once {
			say("watching: %d fuzz container(s) of %d running", seen, total)
			return nil
		}
		select {
		case <-ctx.Done():
			say("stop")
			return ctx.Err()
		case <-time.After(o.Interval):
		}
	}
}

func sweep(ctx context.Context, o Options, say func(string, ...any)) (seen, total int, err error) {
	cs, err := list(ctx)
	if err != nil {
		return 0, 0, err
	}
	total = len(cs)
	for _, c := range cs {
		// The wrapper's name is the only reliable marker that this is a fuzz
		// container at all.
		if !strings.Contains(c.Cmd, "run_fuzzer") && !strings.Contains(c.Cmd, "_fuzz") {
			continue
		}
		seen++
		m := budgetRe.FindStringSubmatch(c.Cmd)
		if m == nil {
			continue
		}
		budget, _ := strconv.Atoi(m[1])
		age := time.Since(c.Started)
		if age <= time.Duration(budget)*time.Second+o.Grace {
			continue
		}

		// Skip run_fuzzer, which is the WRAPPER: matching it would label every
		// kill with the harness name instead of the target that hung, which is
		// the one thing the log exists to record.
		target := ""
		for _, t := range targetRe.FindAllString(c.Cmd, -1) {
			if t != "run_fuzzer" {
				target = t
				break
			}
		}
		say("KILL %s target=%s age=%ds budget=%ds (+%s grace)",
			c.Name, target, int(age.Seconds()), budget, o.Grace)

		if target != "" && signal(ctx, c.ID, target) == nil {
			say("  asked %s to stop (SIGTERM); waiting up to %s for stats", target, o.TermWait)
			waited := time.Duration(0)
			for waited < o.TermWait {
				if !running(ctx, c.ID) {
					break
				}
				time.Sleep(time.Second)
				waited += time.Second
			}
			if !running(ctx, c.ID) {
				say("  %s exited after SIGTERM in %s -- final stats recorded", c.Name, waited)
				continue
			}
			say("  still up after %s; escalating to SIGKILL", waited)
		} else {
			say("  could not signal %s directly; going straight to SIGKILL", target)
		}

		if exec.CommandContext(ctx, "docker", "kill", c.ID).Run() == nil {
			say("  killed %s (no final stats: SIGKILL prints none)", c.Name)
		} else {
			say("  kill FAILED for %s", c.Name)
		}
	}
	return seen, total, nil
}

// list reads the full argv from inspect rather than docker ps.
//
// {{.Command}} is TRUNCATED by docker ps, and the deadline we need is an
// argument, not the image name. The fields are read as JSON rather than
// pipe-joined: the container command contains pipes of its own, and a
// pipe-split of that string once made every container invisible to this
// watchdog while a slice ran twelve hours past an 1800s budget.
func list(ctx context.Context) ([]container, error) {
	ids, err := exec.CommandContext(ctx, "docker", "ps", "-q").Output()
	if err != nil {
		return nil, err
	}
	var out []container
	for _, id := range strings.Fields(string(ids)) {
		b, err := exec.CommandContext(ctx, "docker", "inspect", id).Output()
		if err != nil {
			continue
		}
		var raw []struct {
			Name   string
			State  struct{ StartedAt string }
			Config struct {
				Cmd        []string
				Entrypoint []string
			}
		}
		if json.Unmarshal(b, &raw) != nil || len(raw) == 0 {
			continue
		}
		t, err := time.Parse(time.RFC3339Nano, raw[0].State.StartedAt)
		if err != nil {
			continue
		}
		out = append(out, container{
			ID:      id,
			Name:    strings.TrimPrefix(raw[0].Name, "/"),
			Started: t,
			Cmd: strings.Join(append(append([]string{}, raw[0].Config.Entrypoint...),
				raw[0].Config.Cmd...), " "),
		})
	}
	return out, nil
}

// signal reaches the fuzzer process through this same binary, which the fuzz
// container already has mounted at /pgfuzz.
func signal(ctx context.Context, id, target string) error {
	return exec.CommandContext(ctx, "docker", "exec", id,
		"/pgfuzz", "_signal", target, "TERM").Run()
}

func running(ctx context.Context, id string) bool {
	out, err := exec.CommandContext(ctx, "docker", "ps", "-q", "--no-trunc").Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), id)
}

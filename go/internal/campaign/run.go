package campaign

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"pgfuzz/internal/fuzz"
	"pgfuzz/internal/logs"
)

// Entry is one workspace in the matrix.
type Entry struct {
	Name string
	Dir  string
	// Data is where this entry's corpus, artifacts and lineage live: the
	// workspace for a local run, the campaign's own directory for a sealed
	// one. See campaign.Manifest.Sealed.
	Data    string
	OutDir  string
	Targets []string
	MaxLen  int
	San     string
}

// Config is one campaign.
type Config struct {
	Slug       string
	RunID      string
	Hours      float64
	PerTarget  int
	Jobs       int
	Entries    []Entry
	OnDeadline OnDeadline
	MaxOverrun time.Duration
	Series     Series
	Out        io.Writer

	// Parallel is how many workspaces sweep at once. Zero means one.
	Parallel int

	// Budgets is the tuned per-target time table, applied to every sweep as
	// the shell did. Empty means every target gets PerTarget.
	Budgets fuzz.Budgets

	// AfterSweep runs the gates after each workspace finishes a sweep, and it
	// is a hook rather than a call because campaign must not import ratchet.
	//
	// It exists because the port lost the gating entirely. The shell spliced
	// `ratchet check` then `ratchet update` into every workspace-round, in
	// that order, with the reason stated: updating first raises the floor to
	// include the very round being judged, so the round can never regress.
	// Without a caller the ratchet was a gate nobody ran -- floors never rose
	// and no regression was ever detected unless a human typed the command.
	//
	// SKIPPED WHEN THE SWEEP WAS CUT SHORT. Bounding the clock must not
	// manufacture findings: a workspace that only got through six of its
	// targets has not earned a verdict on the other seventeen.
	// judgeable says why this round must NOT be gated, or "" when it may be.
	// Two different reasons reach it -- a round that never finished, and a
	// round the disk floor cut a slice out of -- and both must stop the
	// ratchet, which otherwise reads an artificially low slice as a
	// regression in the target rather than a fact about the filesystem.
	AfterSweep func(e Entry, round int, complete bool, notJudgeable string)

	// Productivity is ws -> target -> newest new_units, from the ratchet
	// series. Empty means "order by rotation alone", which is what happens
	// before a workspace has any history.
	Productivity map[string]map[string]int
}

// defaultOverrun sizes the backstop from the widest workspace in the campaign.
func defaultOverrun(c Config) time.Duration {
	widest := 1
	for _, e := range c.Entries {
		if n := len(e.Targets); n > widest {
			widest = n
		}
	}
	return time.Duration(c.PerTarget*widest*3) * time.Second
}

// Run executes rounds until the deadline, applying the deadline policy.
func Run(ctx context.Context, c Config) error {
	if c.OnDeadline == "" {
		c.OnDeadline = Cut
	}
	if c.MaxOverrun == 0 {
		// THE BACKSTOP BEHIND THE DEADLINE POLICY, sized as "one more sweep of
		// the widest workspace, and then some".
		//
		// It used to be PerTarget * 23 * 3, where 23 is the number of targets
		// this project happens to have -- so a workspace with more targets got
		// a guard that fires mid-sweep, and one with fewer got a guard three
		// times longer than it needs. Derived from the entries instead.
		//
		// The 3x is not slack for its own sake: at short budgets the container
		// start dominates, and a 15-second slice costs about 45 seconds of
		// wall clock. It is the difference between what a slice is ALLOWED and
		// what it takes.
		c.MaxOverrun = defaultOverrun(c)
	}
	start := time.Now()
	deadline := start.Add(time.Duration(c.Hours * float64(time.Hour)))
	hardStop := deadline.Add(c.MaxOverrun)
	// Serialised, because workspaces now sweep concurrently and two goroutines
	// writing a progress line at once produce one interleaved line -- which is
	// worse than no line, since it looks like a corrupted target name.
	var sayMu sync.Mutex
	say := func(f string, a ...any) {
		if c.Out == nil {
			return
		}
		sayMu.Lock()
		defer sayMu.Unlock()
		fmt.Fprintf(c.Out, f+"\n", a...)
	}

	for round := 1; ; round++ {
		if time.Now().After(deadline) && c.OnDeadline != FinishRound {
			break
		}
		if time.Now().After(hardStop) {
			say("hard stop: overran by %s, round %d left incomplete", c.MaxOverrun, round)
			break
		}
		say("\n=== round %d (%s left) ===", round, time.Until(deadline).Round(time.Minute))

		// ROTATE THE WORKSPACE ORDER, and this is the half that matters more
		// than rotating targets. The order is fixed, so the same arm is always
		// the one that runs out of budget -- and oriolebare* sorts after
		// oriole*, which made the CONTROL arm of a three-way diff the one that
		// got cut. A prime stride so neighbours do not share a fate for long.
		order := rotate(c.Entries, round*7)
		// Within each workspace the TARGETS are ordered most-productive-first
		// when the series says which those are, so a round cut short by the
		// deadline spends what it has where the finding is. Rotation and
		// productivity are not alternatives: rotation is fairness ACROSS
		// rounds, this is value WITHIN one that may not finish.

		// WORKSPACES SWEEP CONCURRENTLY, up to Parallel at a time.
		//
		// The port made this a plain sequential loop and nothing recorded that
		// as a decision. The cost is not subtle: five workspaces take five
		// times the wall clock for the same hours budget, so the last arm of a
		// comparison gets a fraction of the rounds the first one did -- on the
		// campaign that exposed this, gt-pg19 got one round to gt-pg16's two
		// and 15 of 23 targets never ran. The old matrix kept six in flight
		// and noted that serial left the box "at 8 of 32 cores with 74.6%
		// idle".
		//
		// One at a time remains available and is still the default for a
		// single workspace, where concurrency buys nothing.
		sem := make(chan struct{}, c.parallel())
		var wg sync.WaitGroup
		for _, e := range order {
			if time.Now().After(hardStop) {
				break
			}
			if time.Now().After(deadline) {
				if c.OnDeadline == Cut {
					break
				}
				say("past deadline, %s: %s", c.OnDeadline, e.Name)
				if c.OnDeadline == FinishSweep {
					// One more workspace, at full length, then stop. Waited
					// for first: "one more" means one more, not one more
					// alongside whatever is still going.
					wg.Wait()
					// CLAMPED TO THE HARD STOP, not unbounded.
					//
					// This passed a zero deadline, so "one more workspace at
					// full length" meant PerTarget x targets plus a per-slice
					// HangGrace with nothing above it -- and -max-overrun,
					// which exists to bound the campaign's wall clock, did not
					// apply in the one policy that most needs bounding. The
					// shell clamped the extra sweep to HARD_STOP - now for
					// exactly this reason: the ceiling holds even when the
					// policy says keep going.
					runOne(ctx, c, e, round, say, hardStop)
					return nil
				}
			}
			wg.Add(1)
			sem <- struct{}{}
			go func(e Entry) {
				defer wg.Done()
				defer func() { <-sem }()
				runOne(ctx, c, e, round, say, deadline)
			}(e)
		}
		// The round is not over until every workspace in it has finished, or
		// the next round's rotation would overlap this one's slices.
		wg.Wait()
		if time.Now().After(deadline) {
			break
		}
	}
	return nil
}

// runOne sweeps one workspace.
//
// The deadline is passed DOWN, not merely checked between workspaces. Under
// `cut` the clock has to be able to stop a sweep already in progress: checking
// only at workspace boundaries meant a campaign given twelve minutes ran a
// full round of 23 targets first, which is most of an hour. A deadline is a
// promise about when the machine is free, and a check that fires only between
// workspaces does not keep it.
func runOne(ctx context.Context, c Config, e Entry, round int, say func(string, ...any), deadline time.Time) {
	// Most-productive-first WITHIN the workspace, when the series says which
	// those are. Reordered on a COPY of the entry, so nothing else sees it.
	//
	// THE SWEEP THEN ROTATES THIS BY THE ROUND, and both are needed.
	//
	// Productivity alone starves. A target that has not run has no new units,
	// so it sorts last, so it does not run -- the same self-reinforcing shape
	// that once left regex_fuzzer at position 18 of 23 and spi_query at 21,
	// both immediately after being repaired, which is exactly when they most
	// needed the time.
	//
	// Rotation alone wastes. A round cut short by the deadline drops its tail,
	// and with a fixed order that tail is the same targets every time.
	//
	// Composed, the productive targets lead the order and the rotation walks
	// the starting point through it, so a short round loses somewhere
	// different each round and every target reaches an early slot eventually.
	if latest := c.Productivity[e.Name]; len(latest) > 0 {
		e.Targets = ByProductivity(e.Targets, latest)
	}
	say("round %d: sweeping %s", round, e.Name)

	// APPENDED AS EACH SLICE FINISHES, not after the workspace does.
	//
	// The series is the model, and a model written only on the happy path is
	// not one. Batching the whole workspace meant a campaign stopped
	// mid-sweep -- by the deadline, by Ctrl-C, by a kill -9 -- lost every
	// slice it had already completed: twenty minutes of real fuzzing, with
	// nothing on disk to show it happened. Verified during a smoke test, six
	// targets and two minutes in, with an empty series.jsonl.
	//
	// It also removes an attribution guess. The result index used to be
	// mapped back to a target by recomputing the same rotation the sweep
	// applied, and any disagreement between the two silently filed every row
	// under the wrong name. OnDone is handed the target.
	record := func(t string, r fuzz.Result) {
		// A SLICE THAT NEVER RAN WRITES NO ROW.
		//
		// Sweep now reports failures instead of abandoning the round, so this
		// is reached for a target that never started. Recording it would put
		// execs 0, corpus 0, alive false into the series as a MEASUREMENT --
		// and a ratchet reading that sees a target that collapsed, not one
		// whose container failed to start.
		if r.Err != nil {
			return
		}
		st, _ := logs.ParseFile(r.LogPath)
		// The trajectory, from the same log. Without it a slice records what
		// it reached and nothing about whether it moved -- and "cov 6156" is
		// the same line whether the slice added 2,276 edges or none.
		traj := logs.Trajectory{}
		if pts, err := logs.ReadTrajectory(r.LogPath); err == nil {
			traj = logs.Summarise(pts)
		}
		if err := c.Series.Append(Slice{
			RunID: c.RunID, Round: round, Workspace: e.Name, Target: t,
			Started: time.Now().UTC().Format(time.RFC3339),
			// The wall clock the slice TOOK, not the budget it was allowed.
			// A slice killed at 8 minutes and one that ran its full 45
			// seconds are different facts.
			Seconds: int(r.Elapsed.Seconds()), Jobs: c.Jobs, Dict: r.Dict,
			Execs: st.Execs, NewUnits: st.NewUnits,
			Cov: st.Cov, Ft: st.Ft, Corpus: r.CorpusTo,
			// BOTH ends, and this is not symmetry for its own sake. The
			// funnel types corpus_before as a pointer precisely so "absent"
			// and "zero" stay apart -- reading absent as zero says a
			// fifteen-second slice created the entire corpus from nothing.
			// Omitting the field emitted a literal 0, which unmarshals to a
			// NON-nil pointer and defeats that guard exactly.
			CorpusBefore: r.CorpusFrom,
			DiskStop:     r.DiskStop,
			PeakRSS:      st.PeakRSS,
			Hung:         r.Hung,
			// The slice's OWN artifacts, not the directory's total. The
			// total is weeks of accumulation and would read as this run's
			// output on every dashboard that shows it.
			Artifacts:       r.NewArtifacts(),
			ArtifactsBefore: r.ArtifactsFrom, ArtifactsAfter: r.ArtifactsTo,
			Slowest:  st.SlowestUnit,
			CovStart: traj.CovStart, FtStart: traj.FtStart,
			CovGained: traj.CovGainedInRun, FtGained: traj.FtGainedInRun,
			LastNewEdgeAt: traj.LastNewEdgeAt, LastExecSeen: traj.LastExecSeen,
			SaturatedPct: traj.SaturatedPct,
			// Alive means it EXECUTED something. A slice that ran the
			// container and executed nothing is the failure every other
			// number in this row would otherwise hide.
			Alive: st.Execs > 0 || traj.LastExecSeen > 0,
		}); err != nil {
			// Said out loud. A series row that failed to write is a slice
			// that, as far as every later reader is concerned, never ran.
			say("  %s/%s: could not record the slice: %v", e.Name, t, err)
		}
	}

	res, err := fuzz.Sweep(ctx, fuzz.SweepRequest{
		Request: fuzz.Request{
			Workspace: e.Dir, Data: e.Data, Name: e.Name, OutDir: e.OutDir,
			Seconds: c.PerTarget, Jobs: c.Jobs, MaxLen: e.MaxLen,
			Sanitizer: e.San, Lineage: true,
			// The floor, armed for every slice: a campaign grows corpora for
			// hours and is exactly the thing that fills a disk.
			StopFreeGB: fuzz.DefaultStopFreeGB,
		},
		Targets:  e.Targets,
		Budgets:  c.Budgets,
		Rotate:   round,
		Deadline: deadline,
		OnStart:  func(t string, i, n int) { say("  ---- %s ---- (%d/%d)", t, i, n) },
		OnDone:   record,
	})
	if err != nil {
		say("  %s: %v", e.Name, err)
	}
	// A RESULT THAT FAILED TO RUN IS NOT A SWEPT TARGET. Sweep now records
	// failures instead of abandoning the round, so completeness has to count
	// what actually ran rather than how many rows came back.
	ran := 0
	for _, r := range res {
		if r.Err == nil {
			ran++
		} else {
			say("  %s: %v", r.Target, r.Err)
		}
	}
	complete := ran >= len(e.Targets)
	if !complete {
		// Recorded as a fact, not left to be inferred from a log: a round that
		// ran 20 of 23 writes 20 healthy results and passes every gate that
		// judges only what it was handed.
		say("  SHORT ROUND: %d of %d targets never ran", len(e.Targets)-ran, len(e.Targets))
	}
	// A COMPLETE ROUND CAN STILL BE UNJUDGEABLE. Every target ran, so nothing
	// above notices, while one of them was stopped part-way by the disk floor
	// and produced a number that says nothing about the target.
	var cut []string
	for _, r := range res {
		if r.DiskStop {
			cut = append(cut, r.Target)
		}
	}
	if len(cut) > 0 {
		say("  DISK FLOOR cut %d slice(s): %s", len(cut), strings.Join(cut, " "))
	}
	// Said, because it is a finding rather than an accident of the machine:
	// something in that target does not return.
	for _, r := range res {
		if r.Hung {
			say("  !! %s HUNG past its budget and was stopped", r.Target)
		}
	}
	if c.AfterSweep != nil {
		c.AfterSweep(e, round, complete, reasonNotJudgeable(complete, cut))
	}
}

// reasonNotJudgeable says why a round must not be gated, or "" when it may be.
//
// TWO REASONS, and the second is the one that hides. A round that never
// finished is visible from its own count. A round where every target ran and
// one slice was stopped part-way by the disk floor looks complete from every
// angle, and its low number is a fact about the filesystem that the ratchet
// would report as a regression in the target.
func reasonNotJudgeable(complete bool, diskCut []string) string {
	if !complete {
		return "the sweep was cut short"
	}
	if len(diskCut) > 0 {
		return "the disk floor cut " + strings.Join(diskCut, ", ")
	}
	return ""
}

func rotate(in []Entry, by int) []Entry {
	n := len(in)
	if n < 2 {
		return in
	}
	off := ((by % n) + n) % n
	out := make([]Entry, 0, n)
	out = append(out, in[off:]...)
	return append(out, in[:off]...)
}

// parallel is how many workspaces may sweep at once, never fewer than one.
func (c Config) parallel() int {
	if c.Parallel > 1 {
		return c.Parallel
	}
	return 1
}

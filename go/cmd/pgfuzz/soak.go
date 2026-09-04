package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"pgfuzz/internal/workspace"
	"strconv"
	"syscall"
	"time"

	"pgfuzz/internal/build"
	"pgfuzz/internal/campaign"
	"pgfuzz/internal/fuzz"
	"pgfuzz/internal/logs"
	"pgfuzz/internal/wslock"
)

// cmdSoak runs the mode a sweep is not.
//
// A sweep gives every target the same short slice in a fixed order. A soak
// keeps a pool in flight and refills it, with slices long enough that corpus
// replay is a rounding error instead of the whole slice -- which is what
// libFuzzer forces, since it never checks -max_total_time during seed replay.
//
// Missing from the port entirely, and not on the deliberate-drop list.
func cmdSoak(argv []string) int {
	fs := flag.NewFlagSet("soak", flag.ExitOnError)
	ws := fs.String("w", "", "workspace")
	hours := fs.Float64("hours", 1, "how long to run")
	conc := fs.Int("concurrent", 16, "targets in flight")
	jobs := fs.Int("jobs", 1, "libFuzzer workers per target")
	base := fs.Int("base", 90, "fallback budget for a target with no tuned entry")
	mult := fs.Int("mult", 20, "slice = budget * this")
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	if err := fs.Parse(argv); err != nil || *ws == "" {
		fs.Usage()
		return 2
	}
	dir, c, r, err := openWS(*ws)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
		return 2
	}
	lk, err := wslock.Acquire(dir, "soak")
	if err != nil {
		fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
		return 2
	}
	defer lk.Release()
	defer func() {
		if n := fuzz.ReapOwn(); n > 0 {
			fmt.Fprintf(os.Stderr, "stopped %d container(s) started by this soak\n", n)
		}
	}()

	out := buildDir(dir, c, r)
	targets, err := build.Targets(out)
	if err != nil || len(targets) == 0 {
		fmt.Fprintf(os.Stderr, "pgfuzz: nothing built in %s\n", out)
		return 2
	}

	var budgets fuzz.Budgets
	if home, err := r.NeedHome(); err == nil {
		budgets = fuzz.LoadBudgets(filepath.Join(home, "scripts", "target-budgets.tsv"))
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// The preflight tier, as every other fuzzing path has.
	if err := wslock.NeedDisk(dir, fuzz.DefaultPreflightGB, "a soak"); err != nil {
		fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
		return 2
	}

	series := campaign.Series{Path: filepath.Join(dir, "soak-series.jsonl")}
	runID := campaign.RunID("soak", time.Now())
	deadline := time.Now().Add(time.Duration(*hours * float64(time.Hour)))

	fmt.Printf("soak %s: %d targets, %d in flight, slices of budget x%d, until %s\n",
		c.Name, len(targets), *conc, *mult, deadline.Format(time.RFC3339))

	res := fuzz.Soak(ctx, fuzz.SoakRequest{
		Request: fuzz.Request{
			Workspace: dir, Name: c.Name, OutDir: out,
			Seconds: *base, Jobs: *jobs, MaxLen: maxLen(c),
			Sanitizer: c.Sanitizer, Lineage: true,
			// THE BASE-RUNNER, like every other mode.
			//
			// This said gcr.io/oss-fuzz/<project>, the BUILDER image. The
			// wrapper a slice execs -- run_fuzzer -- ships only in
			// base-runner, so every soak slice failed to exec and fuzzed
			// nothing. Leaving the field empty takes fuzz.Request's default,
			// which is the one image run, sweep and campaign all use; naming
			// a second image here is how they came to disagree.
			//
			// The disk floor, which a soak needs more than any other mode: it
			// is the longest-running and most corpus-hungry, and it was the
			// only path with neither tier armed.
			StopFreeGB: fuzz.DefaultStopFreeGB,
		},
		Targets: targets, Concurrent: *conc,
		Budgets: budgets, Multiplier: *mult, Deadline: deadline,
		OnStart: func(t string, n int) {
			fmt.Printf("  ---- %s ---- (%d in flight)\n", t, n)
		},
		OnDone: func(t string, r fuzz.Result, err error) {
			if err != nil {
				fmt.Printf("  %-26s %v\n", t, err)
				return
			}
			fmt.Printf("  %-26s %s  corpus %d -> %d (+%d)  artifacts +%d\n",
				t, r.Elapsed.Round(time.Second), r.CorpusFrom, r.CorpusTo,
				r.CorpusTo-r.CorpusFrom, r.NewArtifacts())
			// Recorded as it finishes, so a killed soak keeps what it did.
			// THE NUMBERS, from the slice's own log.
			//
			// The row carried none: no execs, no new units, no coverage, no
			// liveness. So the mode that does the most fuzzing per slice read
			// as "execs: 0, alive: false" to every consumer of a series row,
			// and contributed nothing to any floor.
			st, _ := logs.ParseFile(r.LogPath)
			series.Append(campaign.Slice{
				RunID: runID, Workspace: c.Name, Target: t,
				Started: time.Now().UTC().Format(time.RFC3339),
				Seconds: int(r.Elapsed.Seconds()), Jobs: *jobs,
				Corpus: r.CorpusTo, CorpusBefore: r.CorpusFrom,
				Artifacts: r.NewArtifacts(), Dict: r.Dict,
				Execs: st.Execs, NewUnits: st.NewUnits,
				Cov: st.Cov, Ft: st.Ft,
				Alive:    st.Startup() == logs.Fuzzed,
				DiskStop: r.DiskStop, Hung: r.Hung,
				PeakRSS: st.PeakRSS,
			})
		},
	})

	fmt.Printf("\nsoak complete: %d slice(s)\n", len(res))
	return 0
}

// maxLen is the workspace's -max_len, stated rather than left to libFuzzer.
//
// libFuzzer picks 4096 cold but silently adopts the largest corpus entry once
// a corpus exists, so the effective limit drifts upward and two runs of "the
// same" target stop being comparable.
func maxLen(c workspace.Conf) int {
	if v := c.Get("max_len"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return 4096
}

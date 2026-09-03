package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"syscall"

	"pgfuzz/internal/repro"
	"pgfuzz/internal/workspace"
)

// cmdTriageSweep reproduces every artifact in a workspace and groups them.
//
// The document-generating half of triage ported well; the ACTING half --
// everything that runs a finding and judges the result -- was deleted with no
// equivalent and no record. This is the first of the two: reproduce all, group
// by normalised signature, and say how many distinct defects are actually in
// a pile of artifacts.
func cmdTriageSweep(argv []string) int {
	fs := flag.NewFlagSet("triage-sweep", flag.ExitOnError)
	ws := fs.String("w", "", "workspace")
	runs := fs.Int("runs", 20, "how many times to run each input")
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

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	results, err := repro.Sweep(ctx, dir, buildDir(dir, c, r),
		"gcr.io/oss-fuzz-base/base-runner:"+workspace.BaseOSVersion(r.OSSFuzz(), c.Project),
		c.Sanitizer, *runs, os.Stderr)
	if err != nil {
		// A REFUSAL, not an empty result. Both of these were paid for: a sweep
		// against an empty build directory reported "131 artifacts, all did
		// not reproduce", and a coverage build succeeds while reporting
		// nothing, which is indistinguishable from "no crash".
		fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
		return 2
	}
	if len(results) == 0 {
		fmt.Println("no artifacts to sweep")
		return 0
	}

	groups := repro.GroupBySignature(results)
	sigs := make([]string, 0, len(groups))
	for s := range groups {
		sigs = append(sigs, s)
	}
	sort.Slice(sigs, func(i, j int) bool {
		if len(groups[sigs[i]]) != len(groups[sigs[j]]) {
			return len(groups[sigs[i]]) > len(groups[sigs[j]])
		}
		return sigs[i] < sigs[j]
	})

	reproduced := 0
	for _, r := range results {
		if r.Verdict == repro.Reproduced {
			reproduced++
		}
	}
	fmt.Printf("\n%d artifact(s), %d reproduced, %d distinct signature(s)\n",
		len(results), reproduced, len(groups))
	for _, s := range sigs {
		g := groups[s]
		targets := map[string]bool{}
		for _, r := range g {
			targets[r.Target] = true
		}
		names := make([]string, 0, len(targets))
		for t := range targets {
			names = append(names, t)
		}
		sort.Strings(names)
		fmt.Printf("\n  %3d  %s\n       %v\n", len(g), s, names)
	}
	return 0
}

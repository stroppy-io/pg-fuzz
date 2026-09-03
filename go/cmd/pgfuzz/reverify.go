package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"pgfuzz/internal/findings"
	"pgfuzz/internal/paths"
	"pgfuzz/internal/repro"
	"pgfuzz/internal/workspace"
)

// cmdReverify re-checks recorded findings: does the record still hold.
//
// The port had no equivalent. `pgfuzz repro` takes one input against one
// workspace and has no notion of a finding, so the rules below -- which
// artifacts count, which vehicle to use, what a skip means -- had to be
// reconstructed by hand every time somebody wanted the answer.
//
// EXIT CODES SAY WHICH ANSWER IT IS: 0 everything still reproduces or was
// skipped with a reason, 1 at least one finding no longer reproduces, 2 could
// not run. A SKIP IS NOT A PASS, and it is never counted as one.
func cmdReverify(argv []string) int {
	fs := flag.NewFlagSet("reverify", flag.ExitOnError)
	root := fs.String("findings", "", "findings directory (default: $PGFUZZ_WS/FINDINGS)")
	only := fs.String("only", "", "one finding by name")
	runs := fs.Int("runs", 20, "how many times to run each input")
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	if err := fs.Parse(argv); err != nil {
		return 2
	}
	r := paths.Resolve()
	dir := *root
	if dir == "" {
		dir = filepath.Join(r.WS, "FINDINGS")
	}
	fs2, err := findings.Scan(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
		return 2
	}
	if len(fs2) == 0 {
		fmt.Fprintf(os.Stderr, "pgfuzz: no findings under %s -- nothing was checked\n", dir)
		return 2
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// RESOLVED BY CAPABILITY, not by name. A write-up that says a finding
	// affects "every major version tested" never named one workspace, and
	// requiring it to would skip every such finding -- which is what the first
	// version of this did, for all 25 on disk.
	//
	// An -add build is preferred because ASan reports the widest class of
	// defect; any workspace with the target built will do otherwise.
	wsFor := func(name string) string {
		if name != "" {
			d := r.Workspace(name)
			if fileExists(filepath.Join(d, "workspace.conf")) {
				return d
			}
		}
		return ""
	}
	byCapability := func(target, prose string) string {
		ents, err := os.ReadDir(r.WS)
		if err != nil {
			return ""
		}
		var cands []string
		for _, e := range ents {
			if !e.IsDir() {
				continue
			}
			d := filepath.Join(r.WS, e.Name())
			c, err := workspace.Load(d)
			if err != nil || c.Sanitizer == "coverage" {
				continue
			}
			if fileExists(filepath.Join(buildDir(d, c, r), target)) {
				cands = append(cands, d)
			}
		}
		// PREFER A WORKSPACE THE WRITE-UP ACTUALLY MENTIONS. Ordering by name
		// alone picked oriole16-add for a finding recorded against stock
		// PostgreSQL, purely because it sorts first -- and then reported "no
		// longer reproduces", which is a statement about the wrong build.
		//
		// After that, an -add build, because ASan reports the widest class of
		// defect; and stock ahead of a flavour, since a finding that does not
		// say otherwise is about PostgreSQL rather than about an extension.
		sort.Slice(cands, func(i, j int) bool {
			ai, aj := filepath.Base(cands[i]), filepath.Base(cands[j])
			if mi, mj := strings.Contains(prose, ai), strings.Contains(prose, aj); mi != mj {
				return mi
			}
			if ia, ja := hasSuffix(ai, "-add"), hasSuffix(aj, "-add"); ia != ja {
				return ia
			}
			if oi, oj := strings.HasPrefix(ai, "oriole"), strings.HasPrefix(aj, "oriole"); oi != oj {
				return oj
			}
			return ai < aj
		})
		if len(cands) == 0 {
			return ""
		}
		return cands[0]
	}

	sort.Slice(fs2, func(i, j int) bool { return fs2[i].Name < fs2[j].Name })
	var gone, skipped, held int
	for _, f := range fs2 {
		if *only != "" && f.Name != *only {
			continue
		}
		fdir := filepath.Join(dir, f.Name)
		p := findings.PlanFor(f, fdir, func(name string) string {
			if d := wsFor(name); d != "" {
				return d
			}
			prose, _ := os.ReadFile(filepath.Join(fdir, "README.md"))
			return byCapability(findings.TargetOf(f), string(prose))
		})
		if p.Skip != "" {
			skipped++
			fmt.Printf("  %-28s SKIP  %s\n", f.Name, p.Skip)
			continue
		}
		if p.Vehicle != findings.LibFuzzer {
			// The other two vehicles need a server; naming them as skipped
			// with the reason beats pretending they were checked.
			skipped++
			fmt.Printf("  %-28s SKIP  %s reproduction is not automated yet\n",
				f.Name, p.Vehicle)
			continue
		}

		_, c, _, err := openWS(filepath.Base(p.Workspace))
		if err != nil {
			skipped++
			fmt.Printf("  %-28s SKIP  %v\n", f.Name, err)
			continue
		}
		image := "gcr.io/oss-fuzz-base/base-runner:" +
			workspace.BaseOSVersion(r.OSSFuzz(), c.Project)
		out := buildDir(p.Workspace, c, r)

		// ANY artifact reproducing means the record holds. Stops at the first
		// one that does: the answer is "yes", and running the other eleven
		// cannot change it.
		outcome := findings.Gone
		for _, a := range p.Artifacts {
			res, _ := repro.Run(ctx, repro.Request{
				Image: image, Out: out, Target: p.Target, Input: a, Runs: *runs,
			})
			if res.Verdict == repro.Reproduced {
				outcome = findings.StillReproduces
				break
			}
			if res.Verdict == repro.Error {
				outcome = findings.Skipped
				break
			}
		}
		switch outcome {
		case findings.StillReproduces:
			held++
			fmt.Printf("  %-28s HOLDS  %s on %s (%d artifact(s))\n",
				f.Name, p.Target, filepath.Base(p.Workspace), len(p.Artifacts))
		case findings.Skipped:
			skipped++
			fmt.Printf("  %-28s SKIP  could not run the reproduction\n", f.Name)
		default:
			gone++
			// NAMES THE WORKSPACE, because "no longer reproduces" is not a
			// fact about the defect until you know what it was checked
			// against. A finding recorded on 17.10 and re-checked on a 19
			// build may be fixed, or may simply not be reachable there --
			// and those call for opposite actions.
			fmt.Printf("  %-28s NO LONGER REPRODUCES on %s  (%s, %d artifact(s) tried)\n",
				f.Name, filepath.Base(p.Workspace), p.Target, len(p.Artifacts))
		}
	}

	fmt.Printf("\n%d hold, %d no longer reproduce, %d skipped\n", held, gone, skipped)
	if gone > 0 {
		fmt.Println("a finding that no longer reproduces has NOT been shown fixed:" +
			" check it was re-run against a build the defect was reachable in")
	}
	if gone > 0 {
		return 1
	}
	return 0
}

func hasSuffix(s, suf string) bool { return len(s) >= len(suf) && s[len(s)-len(suf):] == suf }

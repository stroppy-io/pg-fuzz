// pgfuzz -- the fuzzing tooling as one static binary.
//
// Today it does one thing: run a recorded input against a built target and say
// whether it still reproduces. That is the smallest useful piece and the one
// with an audience outside this machine -- see ../../GO-REWRITE.md.
package main

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"pgfuzz/internal/archive"
	"pgfuzz/internal/breakdown"
	"pgfuzz/internal/build"
	"pgfuzz/internal/bundle"
	"pgfuzz/internal/campaign"
	"pgfuzz/internal/census"
	"pgfuzz/internal/corpus"
	"pgfuzz/internal/coverage"
	"pgfuzz/internal/finalreport"
	"pgfuzz/internal/fuzz"
	"pgfuzz/internal/gate"
	"pgfuzz/internal/incontainer"
	"pgfuzz/internal/inventory"
	"pgfuzz/internal/logs"
	"pgfuzz/internal/paths"
	"pgfuzz/internal/pgserver"
	"pgfuzz/internal/plateau"
	"pgfuzz/internal/ratchet"
	"pgfuzz/internal/redgreen"
	"pgfuzz/internal/report"
	"pgfuzz/internal/repro"
	"pgfuzz/internal/scenario"
	"pgfuzz/internal/seedcorpus"
	"pgfuzz/internal/source"
	"pgfuzz/internal/term"
	"pgfuzz/internal/tidy"
	"pgfuzz/internal/triage"
	"pgfuzz/internal/tui"
	"pgfuzz/internal/watchdog"
	"pgfuzz/internal/workspace"
	"pgfuzz/internal/wslock"
)

const usage = `pgfuzz -- reproduce a recorded finding

  pgfuzz build -w <workspace> [-ref R] [-sanitizer S] [-engine E]
                [-no-disk-check] [-no-stack-check] [-into DIR]
  pgfuzz targets -w <workspace>
  pgfuzz run   -w <workspace> -t <target> [-time S] [-jobs N]
  pgfuzz sweep -w <workspace> [-time S] [-jobs N] [-round N]
  pgfuzz campaign -slug NAME -hours H -w <ws> [-w <ws>...] [-on-deadline P]
                  [-sealed] [-jobs N] [-parallel N] [-time S] [-rebuild]
  pgfuzz report   -slug NAME [-html FILE] [-md FILE]
  pgfuzz report   -final [-prefix P] [-html FILE] [-md FILE] [-data FILE]
                         [-from <archived data.json>]
  pgfuzz report   -exec  [-prefix P] [-html FILE]
  pgfuzz report   -funnel <campaign.jsonl> [-against <other.jsonl>]
  pgfuzz report   -record <campaign.jsonl> [-against <other.jsonl>]
  pgfuzz tui      [<slug>|<path>]   default: the campaign you are standing in
  pgfuzz coverage -w <cov-workspace> [-union] [-measure [-t TARGET]]
                  [-min-free-gb N] [-stop-free-gb N]
  pgfuzz ratchet  -w <workspace> [-update] [-baseline FILE]
                  [-show|-cusum|-activity|-distribution|-variance]
                  [-reseed <target> -reason "..." [-since ISO]]
                  [-profile NAME]   an isolated baseline, series and history
  pgfuzz bootstrap [-cache DIR]
  pgfuzz pin    [-check] [-update -reason "..."] [-pg <ref> [-reason "..."]]
  pgfuzz corpus -w <ws> [-repair] [-seed-from <ws>] [-minimize [-cap N]]
                        [-autocap [-apply] [-tune-budget]]
                        [-seed-from-source <pg-src> [-extra-globs G]]
  pgfuzz ws     [-new NAME -ref R [-flavor F] [-sanitizer S] [-plugins "..."]]
                 with no arguments, lists every workspace
  pgfuzz index  [-slug NAME] [-o FILE]
  pgfuzz bundle -slug NAME [-cov <ws>] [-no-corpus] [-out DIR] [-force]
  pgfuzz stop   [-w <ws>] [-slug NAME]
  pgfuzz watchdog [-grace S] [-interval S] [-n]
  pgfuzz plateau -w <ws> [-w <ws>...] [-window M] [-once]
  pgfuzz tidy   [-apply] [-min-mb N] [-docker]
  pgfuzz plugins -f plugins.tsv [name...]
  pgfuzz inventory [-w <ws>...] [-json]
  pgfuzz triage-report [-o FILE] [-check] [-family F] [-note TEXT]
  pgfuzz redgreen -root <pg-fuzz> [-green] [-case ID]
  pgfuzz triage -w <ws> -t <target> -verdict V <artifact>
  pgfuzz log    -w <ws> -title T [-line L ...]
  pgfuzz census -w <ws> [-w <ws>...] -o DIR
  pgfuzz gate  -w <workspace> [-floor N] [-baseline FILE] [-since D] [-min-stats P]
  pgfuzz soak  -w <ws> [-hours H] [-concurrent N] [-jobs N] [-mult N]
  pgfuzz reverify [-findings DIR] [-only NAME] [-runs N]
  pgfuzz triage-sweep -w <ws> [-runs N]
  pgfuzz archive -slug NAME [-no-corpus] [-force]
  pgfuzz breakdown -w <ws> [-json]
  pgfuzz clone <slug>|<path> <dest>
  pgfuzz reown [-w <ws>] [-all] [-n] [<path>...]
  pgfuzz repro -w <workspace> -t <target> <input>
  pgfuzz sql   -w <workspace> <file.sql>
  pgfuzz scenario -w <workspace> <seedN.json>
  pgfuzz storage  -w <workspace> [-seeds N] [-start-seed N]

    -w   workspace name (under $PGFUZZ_WS) or a path to one
    -t   fuzz target, e.g. xlogreader_fuzzer
    -runs      how many times to run the input (default 100, as OSS-Fuzz does)
    -timeout   give up after this long (default 10m; 0 disables)
    -quiet     verdict only, no container output

  build exit: 0 built, 1 build failed, 2 could not start.

  build is what makes this binary self-sufficient: the harnesses, our
  patches and the build recipe are carried inside it, so a workspace can
  be built without this project's repository existing anywhere. What it
  still needs is docker, git, and the PostgreSQL clone it exports from.

  coverage -union merges every per-target profile and counts each line
  once. A union is NOT the largest member: reporting one target as the
  campaign was caught only because the union came out smaller than one of
  its parts. Plugin .so files are added explicitly, because
  coverage_helper walks DT_NEEDED and PostgreSQL dlopens its extensions.

  ratchet compares each target against its own record rather than a flat
  floor -- simple_query_fuzzer fell from 264,893 executions to 192 and
  every flat gate passed it. -update raises floors that were beaten,
  never lowers one.

  gate  exit: 0 all gates passed, 1 a gate failed, 2 nothing to judge.

  gate runs the checks that fail a round: starvation, slow units, UB sites
  nobody accepted, and whether every built target actually ran. A gate
  that fails is a fact somebody has to acknowledge; a number in a report
  is one somebody has to notice, and this project has printed tables
  across campaigns nobody acted on.

  repro exit: 0 reproduced, 1 clean, 2 could not run.
  sql   exit: 0 server died, 1 server survived, 2 could not run a server.
  scenario exit: 0 reproduced, 1 ran clean, 2 could not run.

  scenario replays a recorded storage finding: tables across tablespaces,
  partitions, concurrent DDL, a deliberate crash, and a consistency check
  after every step. The seed alone does not reproduce these -- the
  generator has changed -- so the recorded .json carries the scenario.

  sql is the vehicle for findings a fuzz target cannot carry -- the ones
  that are "run this against a server and watch". It starts a postmaster
  from the workspace's own build with restart_after_crash=off, because the
  default makes a crashed server reinitialise in seconds and look alive.

  A clean run and a run that could not start are DIFFERENT exit codes on
  purpose. Reading "the image was missing" as "the bug is fixed" is how an
  unreproducible finding reaches a maintainer.

Roots, all overridable, all defaulting under $HOME:
  PGFUZZ_HOME   this repository        PGFUZZ_CACHE  the clones
  PGFUZZ_WS     workspaces and data    PGFUZZ_SRC    patches
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	switch os.Args[1] {
	// Hidden: the in-container half, invoked by the binary mounting itself
	// into a container. Not in the usage text because nobody types these.
	case "_fuzz":
		os.Exit(incontainer.Fuzz(os.Args[2:]))
	case "_repro":
		os.Exit(incontainer.Repro(os.Args[2:]))
	case "_covunion":
		os.Exit(incontainer.CovUnion(os.Args[2:]))
	case "_scenario":
		os.Exit(incontainer.Scenario(os.Args[2:]))
	case "_sql":
		os.Exit(incontainer.SQLOnly(os.Args[2:]))
	case "_own":
		os.Exit(incontainer.Own(os.Args[2:]))
	case "_signal":
		os.Exit(incontainer.Signal(os.Args[2:]))
	case "build":
		os.Exit(cmdBuild(os.Args[2:]))
	case "targets":
		os.Exit(cmdTargets(os.Args[2:]))
	case "run":
		os.Exit(cmdRun(os.Args[2:]))
	case "sweep":
		os.Exit(cmdSweep(os.Args[2:]))
	case "campaign":
		os.Exit(cmdCampaign(os.Args[2:]))
	case "tui":
		os.Exit(cmdTUI(os.Args[2:]))
	case "report":
		os.Exit(cmdReport(os.Args[2:]))
	case "coverage":
		os.Exit(cmdCoverage(os.Args[2:]))
	case "ratchet":
		os.Exit(cmdRatchet(os.Args[2:]))
	case "pin":
		os.Exit(cmdPin(os.Args[2:]))
	case "bootstrap":
		os.Exit(cmdBootstrap(os.Args[2:]))
	case "triage":
		os.Exit(cmdTriage(os.Args[2:]))
	case "log":
		os.Exit(cmdLog(os.Args[2:]))
	case "stop":
		os.Exit(cmdStop(os.Args[2:]))
	case "watchdog":
		os.Exit(cmdWatchdog(os.Args[2:]))
	case "plateau":
		os.Exit(cmdPlateau(os.Args[2:]))
	case "tidy":
		os.Exit(cmdTidy(os.Args[2:]))
	case "plugins":
		os.Exit(cmdPlugins(os.Args[2:]))
	case "inventory":
		os.Exit(cmdInventory(os.Args[2:]))
	case "triage-report":
		os.Exit(cmdTriageReport(os.Args[2:]))
	case "redgreen":
		os.Exit(cmdRedGreen(os.Args[2:]))
	case "corpus":
		os.Exit(cmdCorpus(os.Args[2:]))
	case "bundle":
		os.Exit(cmdBundle(os.Args[2:]))
	case "index":
		os.Exit(cmdIndex(os.Args[2:]))
	case "ws":
		os.Exit(cmdWS(os.Args[2:]))
	case "census":
		os.Exit(cmdCensus(os.Args[2:]))
	case "gate":
		os.Exit(cmdGate(os.Args[2:]))
	case "soak":
		os.Exit(cmdSoak(os.Args[2:]))
	case "reverify":
		os.Exit(cmdReverify(os.Args[2:]))
	case "triage-sweep":
		os.Exit(cmdTriageSweep(os.Args[2:]))
	case "archive":
		os.Exit(cmdArchive(os.Args[2:]))
	case "breakdown":
		os.Exit(cmdBreakdown(os.Args[2:]))
	case "clone":
		os.Exit(cmdClone(os.Args[2:]))
	case "reown":
		os.Exit(cmdReown(os.Args[2:]))
	case "repro":
		os.Exit(cmdRepro(os.Args[2:]))
	case "sql":
		os.Exit(cmdSQL(os.Args[2:]))
	case "storage":
		os.Exit(cmdStorage(os.Args[2:]))
	case "scenario":
		os.Exit(cmdScenario(os.Args[2:]))
	case "-h", "--help", "help":
		fmt.Print(usage)
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
}

func cmdRepro(argv []string) int {
	fs := flag.NewFlagSet("repro", flag.ExitOnError)
	ws := fs.String("w", "", "workspace name or path")
	target := fs.String("t", "", "fuzz target")
	runs := fs.Int("runs", 100, "how many times to run the input")
	timeout := fs.Duration("timeout", 10*time.Minute, "give up after this long (0 disables)")
	quiet := fs.Bool("quiet", false, "verdict only")
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	if err := fs.Parse(argv); err != nil {
		return 2
	}
	if *ws == "" || *target == "" || fs.NArg() != 1 {
		fs.Usage()
		return 2
	}
	input := fs.Arg(0)

	r := paths.Resolve()
	dir := *ws
	if !filepath.IsAbs(dir) && !fileExists(filepath.Join(dir, "workspace.conf")) {
		dir = r.Workspace(*ws)
	}
	conf, err := workspace.Load(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
		return 2
	}

	req := repro.Request{
		Image:   "gcr.io/oss-fuzz-base/base-runner:" + workspace.BaseOSVersion(r.OSSFuzz(), conf.Project),
		Out:     r.Out(conf.Project),
		Target:  *target,
		Input:   input,
		Runs:    *runs,
		Timeout: *timeout,
		Scratch: filepath.Join(dir, "reprotmp"),
	}
	if !*quiet {
		req.Stream = os.Stderr
		fmt.Fprintf(os.Stderr, "==> %s / %s\n    build   %s\n    input   %s\n\n",
			conf.Name, *target, req.Out, input)
	}

	// Ctrl-C should stop the container, not orphan it.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	res, err := repro.Run(ctx, req)
	fmt.Printf("\n%s  %s  %s  (%s)\n", res.Verdict, conf.Name, *target,
		res.Elapsed.Round(time.Millisecond))
	if res.Signature != "" {
		fmt.Printf("  %s\n", res.Signature)
	}
	switch res.Verdict {
	case repro.Reproduced:
		return 0
	case repro.Clean:
		fmt.Printf("  ran %d times without a sanitizer report\n", *runs)
		return 1
	default:
		fmt.Fprintf(os.Stderr, "  %v\n", err)
		return 2
	}
}

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }

func cmdSQL(argv []string) int {
	fs := flag.NewFlagSet("sql", flag.ExitOnError)
	ws := fs.String("w", "", "workspace name or path")
	timeout := fs.Duration("timeout", 15*time.Minute, "give up after this long")
	quiet := fs.Bool("quiet", false, "verdict only")
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	if err := fs.Parse(argv); err != nil {
		return 2
	}
	if *ws == "" || fs.NArg() != 1 {
		fs.Usage()
		return 2
	}

	r := paths.Resolve()
	dir := *ws
	if !filepath.IsAbs(dir) && !fileExists(filepath.Join(dir, "workspace.conf")) {
		dir = r.Workspace(*ws)
	}
	conf, err := workspace.Load(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
		return 2
	}

	req := pgserver.Request{
		// The BUILDER image, not base-runner: it has the icu and readline the
		// server and psql link against. base-runner does not, and psql that
		// cannot start prints nothing while the harness announces a crash it
		// never caused -- which is what mchar's bundle did until 2026-08-18.
		Image:   "gcr.io/oss-fuzz/" + conf.Project,
		Out:     r.Out(conf.Project),
		SQL:     fs.Arg(0),
		Timeout: *timeout,
	}
	if !*quiet {
		req.Stream = os.Stderr
		fmt.Fprintf(os.Stderr, "==> %s\n    build   %s\n    sql     %s\n\n",
			conf.Name, req.Out, req.SQL)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	res, err := pgserver.Run(ctx, req)
	fmt.Printf("\n%s  %s  (%s)\n", res.Outcome, conf.Name, res.Elapsed.Round(time.Millisecond))
	if res.Marker != "" {
		fmt.Printf("  %s\n", res.Marker)
	}
	switch res.Outcome {
	case pgserver.ServerDied:
		return 0
	case pgserver.Survived, pgserver.Errored:
		return 1
	default:
		fmt.Fprintf(os.Stderr, "  %v\n", err)
		return 2
	}
}

func cmdScenario(argv []string) int {
	fs := flag.NewFlagSet("scenario", flag.ExitOnError)
	ws := fs.String("w", "", "workspace name or path")
	timeout := fs.Duration("timeout", 20*time.Minute, "give up after this long")
	dump := fs.Bool("dump", false, "print the driver script and stop")
	quiet := fs.Bool("quiet", false, "verdict only")
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	if err := fs.Parse(argv); err != nil {
		return 2
	}
	if fs.NArg() != 1 || (*ws == "" && !*dump) {
		fs.Usage()
		return 2
	}

	raw, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
		return 2
	}
	rec, err := scenario.UnmarshalStrict(raw)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
		return 2
	}
	if *dump {
		// The driver is Go now, so there is no script to print. The SETUP is
		// still worth showing: it is what the goldens check.
		fmt.Print(scenario.RenderSetup(rec.Scenario))
		return 0
	}

	r := paths.Resolve()
	dir := *ws
	if !filepath.IsAbs(dir) && !fileExists(filepath.Join(dir, "workspace.conf")) {
		dir = r.Workspace(*ws)
	}
	conf, err := workspace.Load(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
		return 2
	}

	req := pgserver.Request{
		Image:    "gcr.io/oss-fuzz/" + conf.Project,
		Out:      r.Out(conf.Project),
		Scenario: fs.Arg(0),
		Timeout:  *timeout,
	}
	if !*quiet {
		req.Stream = os.Stderr
		fmt.Fprintf(os.Stderr, "==> %s  seed %d\n    expected: %s\n\n",
			conf.Name, rec.Seed, rec.Failure)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	res, err := pgserver.Run(ctx, req)
	got := scenario.ResultLine(res.Output)
	fmt.Printf("\n%s  seed %d  (%s)\n", verdictWord(got), rec.Seed, res.Elapsed.Round(time.Second))
	if got != "" {
		fmt.Printf("  got:      %s\n", got)
		fmt.Printf("  expected: %s\n", rec.Failure)
	}
	switch {
	case got == "":
		fmt.Fprintf(os.Stderr, "  %v\n", err)
		return 2
	case strings.HasPrefix(got, "setup-failed:"):
		// Not a reproduction and not a clean run: the scenario never got
		// built, so it says nothing either way about the defect.
		return 2
	case got == "clean":
		return 1
	default:
		return 0
	}
}

func verdictWord(got string) string {
	switch {
	case got == "":
		return "COULD NOT RUN"
	case strings.HasPrefix(got, "setup-failed:"):
		return "COULD NOT BUILD THE SCENARIO"
	case got == "clean":
		return "ran clean -- did NOT reproduce"
	default:
		return "REPRODUCED"
	}
}

func cmdBuild(argv []string) int {
	fs := flag.NewFlagSet("build", flag.ExitOnError)
	ws := fs.String("w", "", "workspace name or path")
	ref := fs.String("ref", "", "git ref to build (default: the workspace's)")
	san := fs.String("sanitizer", "", "address | undefined | coverage")
	eng := fs.String("engine", "", "libfuzzer")
	plugins := fs.String("plugins", "", "plugins.tsv to use (default: the repo's)")
	into := fs.String("into", "", "build into this directory instead of the workspace's builds/")
	keepSrc := fs.Bool("keep-src", false, "keep the exported source tree")
	noDisk := fs.Bool("no-disk-check", false, "build even with little free space")
	noStackCheck := fs.Bool("no-stack-check", false, "build even without the ASan stack-depth fix")
	noPin := fs.Bool("no-pin", false, "build against whatever substrate is present, ignoring the pin")
	timeout := fs.Duration("timeout", 90*time.Minute, "give up after this long")
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	if err := fs.Parse(argv); err != nil {
		return 2
	}
	if *ws == "" {
		fs.Usage()
		return 2
	}

	r := paths.Resolve()
	dir := *ws
	if !filepath.IsAbs(dir) && !fileExists(filepath.Join(dir, "workspace.conf")) {
		dir = r.Workspace(*ws)
	}
	conf, err := workspace.Load(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
		return 2
	}
	pick := func(flagv, confv, def string) string {
		if flagv != "" {
			return flagv
		}
		if confv != "" {
			return confv
		}
		return def
	}
	useRef := pick(*ref, conf.Ref, "")
	useSan := pick(*san, conf.Sanitizer, "address")
	useEng := pick(*eng, conf.Get("engine"), "libfuzzer")
	if useRef == "" {
		fmt.Fprintln(os.Stderr, "pgfuzz: no ref: pass -ref or set ref= in workspace.conf")
		return 2
	}

	// OrioleDB workspaces export a different repository.
	repoDir := filepath.Join(r.Cache, "postgres")
	orioleRepo := filepath.Join(r.Cache, "orioledb")
	isOriole := conf.Get("flavor") == "orioledb"
	if isOriole {
		repoDir = filepath.Join(r.Cache, "orioledb-postgres")

		// A BARE MAJOR IS NOT A BUILDABLE REF. OrioleDB refuses to build
		// against any patchset commit but its own, so `ref=17` has to be
		// resolved through the extension's .pgtags -- read out of the resolved
		// ref rather than off disk, because `git fetch` advances
		// refs/remotes/origin/main and touches neither the local branch nor
		// the checkout.
		//
		// The port dropped this, so the 23 workspaces here naming ref=16|17|18
		// simply failed to build. The quieter hazard was one step away:
		// build.sh keys the whole extension path on
		// orioledb/orioledb.control existing in the export, so a bare ref that
		// DID resolve would have produced a fork-without-extension build
		// indistinguishable from a real OrioleDB one.
		if source.IsBareMajor(useRef) {
			pinned, err := source.PatchsetFor(orioleRepo, conf.Get("orioledb_ref"), useRef)
			if err != nil {
				fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
				return 2
			}
			fmt.Fprintf(os.Stderr, "    OrioleDB pins PostgreSQL %s to %s\n", useRef, pinned)
			useRef = pinned
		}
	}
	repo := source.Repo{Dir: repoDir}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if os.Getenv("PGFUZZ_NO_FETCH") != "1" {
		fmt.Fprintf(os.Stderr, "==> refreshing %s\n", filepath.Base(repoDir))
		if err := repo.Fetch(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "    %v\n", err)
		}
	}

	// REFUSED, not queued. A build replaces the directory running fuzzers are
	// executing out of, so starting one under a live sweep swaps binaries
	// beneath a container that is mid-slice.
	lk, err := wslock.Acquire(dir, "build")
	if err != nil {
		fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
		return 2
	}
	defer lk.Release()

	// A build writes a PostgreSQL tree twice plus docker layers. Out of space
	// part-way through surfaces as an unrelated write failing much later.
	if !*noDisk {
		if err := wslock.NeedDisk(dir, 15, "a build"); err != nil {
			fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
			return 2
		}
	}

	src := filepath.Join(dir, "src")
	fmt.Fprintf(os.Stderr, "==> exporting %s\n", useRef)
	short, full, err := repo.Export(ctx, useRef, src, os.Stderr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
		return 2
	}

	// THE POSTGRESQL PIN, checked the same way the substrate pin is. A pinned
	// ref that has moved means this build is not the experiment the pin
	// describes -- and unlike the substrate, the drift is invisible: the
	// branch name still resolves, just to something else.
	if !*noPin {
		if pins, err := archive.ReadPGPin(r.Home); err == nil {
			if bad := pins.Check(repo.Dir, useRef, full); bad != "" {
				fmt.Fprintf(os.Stderr, "pgfuzz: %s\n", bad)
				return 2
			}
		}
	}

	// REFUSED BEFORE THE CONTAINER STARTS, and only for ASan. A tree without
	// upstream's use-after-return stack-depth fix cannot execute a single
	// utility statement under AddressSanitizer, and says nothing about it --
	// it reports healthy execution counts and accumulates coverage. patch= is
	// consulted first, since a workspace pinned to an older minor may carry
	// the cherry-pick.
	if !*noStackCheck {
		if err := build.CheckStackFix(repo.Dir, full, useSan, conf.Get("patch")); err != nil {
			fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
			return 2
		}
	}
	moving := ""
	if repo.IsMoving(ctx, useRef) {
		// Said out loud: a finding against a branch means nothing without the
		// commit it resolved to, and that is the number that goes in a report.
		moving = "  (moving branch -- this build is " + short + ")"
	}
	fmt.Fprintf(os.Stderr, "    %s %s%s\n", useRef, short, moving)

	if *plugins == "" {
		if p := filepath.Join(r.Home, "project", "plugins.tsv"); fileExists(p) {
			*plugins = p
		}
	}
	// THE SUBSTRATE MUST MATCH THE PIN BEFORE ANYTHING IS BUILT.
	//
	// Refused, not warned. A build against a different oss-fuzz commit
	// succeeds and produces binaries that look exactly like the pinned ones --
	// the difference only shows up later as a fingerprint that moved, by which
	// point the corpus has grown on the wrong substrate and the comparison it
	// was grown for is gone. -no-pin exists for deliberately testing a new
	// substrate, and it says so on every line it prints.
	if !*noPin {
		if pin, err := archive.ReadPin(r.Home); err == nil {
			if bad := pin.Check(r.OSSFuzz()); len(bad) > 0 {
				fmt.Fprintf(os.Stderr, "pgfuzz: the substrate does not match %s:\n", archive.PinFile)
				for _, m := range bad {
					fmt.Fprintln(os.Stderr, m)
				}
				fmt.Fprintf(os.Stderr, "  Build anyway with -no-pin, or move the pin with\n"+
					"  `pgfuzz pin -update -reason \"...\"` if the change is intended.\n")
				return 2
			}
		} else if !os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
			return 2
		}
	}

	// THE EXTENSION, exported beside the fork. build.sh keys the whole
	// orioledb path on orioledb/orioledb.control existing here, so without
	// this the build succeeds as a fork-only build and nothing says so.
	if isOriole && conf.Get("orioledb_extension") != "no" {
		oref := source.ResolvedRef(orioleRepo, conf.Get("orioledb_ref"))
		dst := filepath.Join(src, "orioledb")
		if err := source.ExportTree(orioleRepo, oref, dst); err != nil {
			fmt.Fprintf(os.Stderr, "pgfuzz: exporting orioledb: %v\n", err)
			return 2
		}
		sha := source.OrioleCommit(orioleRepo, conf.Get("orioledb_ref"))
		fmt.Fprintf(os.Stderr, "    orioledb %s (%s) exported\n", oref, sha)
		// Recorded, because a fork-only build and a real OrioleDB build are
		// otherwise indistinguishable after the fact.
		if err := workspace.Set(dir, "orioledb_sha", sha); err != nil {
			fmt.Fprintf(os.Stderr, "pgfuzz: recording orioledb_sha: %v\n", err)
		}
	}

	// The workspace's own patch series, against the export, before anything
	// else touches it. A workspace that declares patches and builds without
	// them produces a tree that everything downstream labels "patched".
	if list := conf.Get("patch"); list != "" {
		fmt.Fprintf(os.Stderr, "==> applying the workspace patch series\n")
		applied, err := build.ApplyPatches(src, strings.Fields(list), os.Stderr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
			return 2
		}
		// Recorded, because workspace.conf's patch_applied= is what the
		// inventory hashes into the fingerprint. Left unwritten it asserts
		// patches that are not in the binary.
		if err := workspace.Set(dir, "patch_applied", strings.Join(applied, " ")); err != nil {
			fmt.Fprintf(os.Stderr, "pgfuzz: recording patch_applied: %v\n", err)
		}
	}

	// The workspace's own plugins, into the source export where build.sh
	// looks for them. A workspace that names none is the common case and
	// costs nothing; one that names twelve must not build without them.
	if list := conf.Get("plugins"); list != "" {
		reg, err := build.ReadPlugins(*plugins)
		if err != nil {
			fmt.Fprintf(os.Stderr, "pgfuzz: reading the plugin registry: %v\n", err)
			return 2
		}
		fmt.Fprintf(os.Stderr, "==> exporting plugins\n")
		if err := build.ExportPlugins(list, reg,
			filepath.Join(r.Cache, "plugins"), src, os.Stderr); err != nil {
			fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
			return 2
		}
	}

	if err := build.Prepare(r.OSSFuzz(), conf.Project, *plugins); err != nil {
		fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
		return 2
	}

	req := build.Request{
		OSSFuzz:   r.OSSFuzz(),
		Project:   conf.Project,
		SrcDir:    src,
		OutDir:    r.Out(conf.Project),
		Sanitizer: useSan,
		Engine:    useEng,
		Env:       build.EnvFor(conf),
		Stream:    os.Stderr,
		Timeout:   *timeout,
	}
	fmt.Fprintf(os.Stderr, "==> building builder image (%s)\n", conf.Project)
	if err := build.Image(ctx, req); err != nil {
		fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "==> building fuzzers: ref=%s sanitizer=%s engine=%s\n",
		useRef, useSan, useEng)
	res, err := build.Fuzzers(ctx, req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\nBUILD FAILED after %s\n%v\n",
			res.Elapsed.Round(time.Second), err)
		return 1
	}

	key := workspace.Key(useRef, useSan, useEng)
	// A campaign builds into its OWN directory. A workspace build is
	// overwritten by the next build of that workspace, and after that the
	// campaign's results describe binaries that no longer exist -- so a
	// coverage rerun measures something else while reporting the campaign's
	// name. That is not hypothetical: a coverage build once spent two days
	// measuring stock orafce while the fuzzing builds ran the patched one.
	dest := filepath.Join(dir, "builds", key)
	if *into != "" {
		dest = *into
	}
	if err := build.Move(req.OutDir, dest); err != nil {
		fmt.Fprintf(os.Stderr, "pgfuzz: moving the build into the workspace: %v\n", err)
		return 1
	}
	os.Symlink(dest, req.OutDir)
	if !*keepSrc {
		// The export is only needed while building; the fuzzers run out of
		// builds/. At ~2.6 GB a workspace that is dead weight, and
		// re-exporting takes seconds.
		os.RemoveAll(src)
	}
	for k, v := range map[string]string{
		"ref": useRef, "sha": short, "sanitizer": useSan,
		"engine": useEng, "key": key,
	} {
		if err := workspace.Set(dir, k, v); err != nil {
			fmt.Fprintf(os.Stderr, "pgfuzz: recording %s: %v\n", k, err)
		}
	}

	// THE WORK LOG. Every build and run appending automatically is a stated
	// rule of this project, and appendWorklog was called only by triage and
	// log -- so the workspace's WORKLOG.md had a hole where every build was.
	appendWorklog(dir, fmt.Sprintf("build %s", key), []string{
		fmt.Sprintf("ref %s at %s", useRef, full),
		fmt.Sprintf("sanitizer %s, engine %s", useSan, useEng),
		fmt.Sprintf("%d targets in %s", len(res.Targets), dest),
		fmt.Sprintf("took %s", res.Elapsed.Round(time.Second)),
	})

	fmt.Printf("\nbuilt  %s  %s  %s/%s  (%s)\n", conf.Name, key, useSan, useEng,
		res.Elapsed.Round(time.Second))
	fmt.Printf("  %d targets  %s\n", len(res.Targets), dest)
	fmt.Printf("  commit %s\n", full)
	return 0
}

// openWS resolves a workspace argument to its directory, config and build.
// openWS resolves a workspace by name or path, and ALWAYS returns an absolute
// directory.
//
// Absolute because the path becomes a docker bind mount. A relative one --
// which is what `pgfuzz run -w gt-pg17` produces when run from inside
// $PGFUZZ_WS, since the local directory matches first -- is rejected by docker
// as a volume NAME:
//
//	create gt-pg17/corpus/simple_query_fuzzer: includes invalid characters
//	for a local volume name ... If you intended to pass a host directory,
//	use absolute path
//
// So the tool worked from one directory and not from the obvious one.
func openWS(name string) (string, workspace.Conf, paths.Roots, error) {
	r := paths.Resolve()
	dir := name
	if !filepath.IsAbs(dir) && !fileExists(filepath.Join(dir, "workspace.conf")) {
		dir = r.Workspace(name)
	}
	if abs, err := filepath.Abs(dir); err == nil {
		dir = abs
	}
	c, err := workspace.Load(dir)
	return dir, c, r, err
}

// buildDir is where this workspace's targets actually live.
//
// The build directory, not the oss-fuzz output symlink: the symlink is shared
// state that another workspace's build repoints, and a run following it would
// silently fuzz somebody else's binaries.
func buildDir(dir string, c workspace.Conf, r paths.Roots) string {
	if k := c.Get("key"); k != "" {
		if p := filepath.Join(dir, "builds", k); fileExists(p) {
			return p
		}
	}
	return r.Out(c.Project)
}

func cmdTargets(argv []string) int {
	fs := flag.NewFlagSet("targets", flag.ExitOnError)
	ws := fs.String("w", "", "workspace")
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
	ts, err := build.Targets(buildDir(dir, c, r))
	if err != nil {
		fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
		return 2
	}
	for _, t := range ts {
		fmt.Println(t)
	}
	return 0
}

func cmdRun(argv []string) int {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	ws := fs.String("w", "", "workspace")
	target := fs.String("t", "", "target")
	secs := fs.Int("time", 600, "seconds to fuzz")
	jobs := fs.Int("jobs", 1, "parallel jobs")
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	if err := fs.Parse(argv); err != nil || *ws == "" || *target == "" {
		fs.Usage()
		return 2
	}
	dir, c, r, err := openWS(*ws)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
		return 2
	}

	// A rebuild replaces the binaries this is about to execute, so hold the
	// workspace for the duration rather than discover it mid-slice.
	lk, lerr := wslock.Acquire(dir, "fuzzing")
	if lerr != nil {
		fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", lerr)
		return 2
	}
	defer lk.Release()

	// THE CONTAINERS GO WITH US. `docker run` is a client and the container is
	// a child of dockerd, so an interrupt takes down the client and leaves the
	// fuzzer running -- the stop command's own comment records "eighteen
	// containers kept fuzzing". Scoped to this process's own containers by the
	// pid in their name.
	defer func() {
		if n := fuzz.ReapOwn(); n > 0 {
			fmt.Fprintf(os.Stderr, "stopped %d container(s) started by this run\n", n)
		}
	}()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	res, err := fuzz.Run(ctx, requestFor(dir, c, r, *target, *secs, *jobs))
	if err != nil {
		fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
		return 2
	}
	reportSlice(*target, res)
	return 0
}

func requestFor(dir string, c workspace.Conf, r paths.Roots, target string, secs, jobs int) fuzz.Request {
	maxLen := 4096
	if v := c.Get("max_len"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			maxLen = n
		}
	}
	return fuzz.Request{
		Workspace: dir,
		Name:      c.Name,
		OutDir:    buildDir(dir, c, r),
		Target:    target,
		Seconds:   secs,
		Jobs:      jobs,
		MaxLen:    maxLen,
		Sanitizer: c.Sanitizer,
		Lineage:   os.Getenv("PGFUZZ_LINEAGE_ON") != "0",
		Stream:    os.Stderr,
		// The running floor. A sweep writes corpus continuously too.
		StopFreeGB: fuzz.DefaultStopFreeGB,
	}
}

func reportSlice(target string, res fuzz.Result) {
	// "+N new" rather than the directory's total: the total is every artifact
	// this target has ever produced, and printing it after a slice reads as
	// what the slice just found.
	fmt.Printf("%-26s %5s  corpus %d -> %d (+%d)  artifacts +%d (%d kept)\n",
		target, res.Elapsed.Round(time.Second), res.CorpusFrom, res.CorpusTo,
		res.CorpusTo-res.CorpusFrom, res.NewArtifacts(), res.ArtifactsTo)
}

func cmdSweep(argv []string) int {
	fs := flag.NewFlagSet("sweep", flag.ExitOnError)
	ws := fs.String("w", "", "workspace")
	secs := fs.Int("time", 600, "seconds per target")
	jobs := fs.Int("jobs", 1, "parallel jobs")
	round := fs.Int("round", 0, "round number; rotates the target order")
	deadline := fs.Duration("deadline", 0, "stop starting targets after this long")
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

	// A rebuild replaces the binaries this is about to execute, so hold the
	// workspace for the duration rather than discover it mid-slice.
	lk, lerr := wslock.Acquire(dir, "fuzzing")
	if lerr != nil {
		fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", lerr)
		return 2
	}
	defer lk.Release()

	// THE CONTAINERS GO WITH US. `docker run` is a client and the container is
	// a child of dockerd, so an interrupt takes down the client and leaves the
	// fuzzer running -- the stop command's own comment records "eighteen
	// containers kept fuzzing". Scoped to this process's own containers by the
	// pid in their name.
	defer func() {
		if n := fuzz.ReapOwn(); n > 0 {
			fmt.Fprintf(os.Stderr, "stopped %d container(s) started by this run\n", n)
		}
	}()
	// PREFLIGHT, the cheap tier: refuse to start below it rather than run into
	// ENOSPC mid-corpus-write hours later. The floor that stops a RUNNING
	// slice is armed separately, in the request.
	if err := wslock.NeedDisk(dir, fuzz.DefaultPreflightGB, "a sweep"); err != nil {
		fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
		return 2
	}
	out := buildDir(dir, c, r)
	targets, err := build.Targets(out)
	targets = selectTargets(c, targets)
	if err != nil || len(targets) == 0 {
		fmt.Fprintf(os.Stderr, "pgfuzz: nothing built in %s\n", out)
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	sr := fuzz.SweepRequest{
		Request: requestFor(dir, c, r, "", *secs, *jobs),
		Targets: targets,
		Rotate:  *round,
		OnStart: func(t string, i, n int) {
			fmt.Fprintf(os.Stderr, "\n---- %s ----  (%d/%d)\n", t, i, n)
		},
		OnDone: func(t string, res fuzz.Result) { reportSlice(t, res) },
	}
	if *deadline > 0 {
		sr.Deadline = time.Now().Add(*deadline)
	}
	results, err := fuzz.Sweep(ctx, sr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
		return 2
	}
	var newInputs, arts int
	for _, res := range results {
		newInputs += res.CorpusTo - res.CorpusFrom
		arts += res.NewArtifacts()
	}
	fmt.Printf("\nswept %d/%d targets  +%d inputs  %d artifacts\n",
		len(results), len(targets), newInputs, arts)
	if len(results) < len(targets) {
		// Said plainly. A round that ran 20 of 23 writes 20 healthy results
		// and passes every gate that judges only what it was handed.
		fmt.Printf("SHORT ROUND: %d targets never ran\n", len(targets)-len(results))
		return 1
	}
	return 0
}

func cmdGate(argv []string) int {
	fs := flag.NewFlagSet("gate", flag.ExitOnError)
	ws := fs.String("w", "", "workspace")
	floor := fs.Int("floor", 10000, "executions below this is starvation")
	baseline := fs.String("baseline", "", "ubsan accept-list (default: the repo's)")
	since := fs.Duration("since", 0, "only judge logs written within this window")
	minStats := fs.Int("min-stats", 90, "percent of slices that must report final stats")
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
	if *baseline == "" {
		home, err := r.NeedHome()
		if err != nil {
			fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
			return 2
		}
		*baseline = filepath.Join(home, "scripts", "ubsan-baseline.tsv")
	}
	accepted, err := gate.LoadAccepted(*baseline)
	if err != nil {
		// Not fatal, but never silent: without the list every accepted site
		// reads as new, and a gate that cries wolf gets switched off.
		fmt.Fprintf(os.Stderr, "pgfuzz: no accept-list (%v) -- every UB site will read as new\n", err)
	}

	// THE NEWEST LOG PER TARGET, not every log the workspace has ever kept.
	//
	// artifacts/<target>/ accumulates a log per run. Globbing all of them
	// judged this round against every round since the workspace was created --
	// including empty logs from runs that died at startup weeks ago, which
	// reported "no executed-unit count" for 24 targets on a workspace that had
	// just executed 33.9 million inputs. The gate then failed the round on the
	// history rather than on the run.
	// SCOPED, or it says it is not.
	//
	// RoundComplete asks "did every built target run", and handing it the
	// newest log per target with no time bound answers a different question:
	// a target that last ran a week ago counts as swept, so the gate written
	// to catch a short round passes every short round. The old check carried
	// an explicit --since because round numbers restart and a shorter
	// campaign leaves the previous one's logs in place.
	all := gatherRunLogs(dir)
	runLogs := newestPerTarget(all)
	if *since > 0 {
		cut := time.Now().Add(-*since)
		var recent []string
		for _, lg := range runLogs {
			if fi, err := os.Stat(lg); err == nil && fi.ModTime().After(cut) {
				recent = append(recent, lg)
			}
		}
		fmt.Printf("  judging %d of %d target log(s) written in the last %s\n",
			len(recent), len(runLogs), *since)
		runLogs = recent
	} else {
		// Said out loud rather than assumed. An unscoped verdict is still
		// worth having; believing it is a verdict on THIS round is not.
		fmt.Printf("  judging every target's newest log, of any age" +
			" -- pass -since to scope this to one round\n")
	}
	if len(runLogs) == 0 {
		// NOT a pass. A gate with nothing to read has checked nothing, and
		// that is not the same as finding nothing wrong.
		fmt.Fprintf(os.Stderr, "pgfuzz: no run logs under %s -- nothing was checked\n", dir)
		return 2
	}

	// The same acknowledgement list the ratchet uses. A starvation floor
	// nobody can acknowledge is a floor people learn to ignore.
	starveAcks := map[string]string{}
	if pp, err := profilePaths(r, ""); err == nil {
		starveAcks, _ = ratchet.LoadAcks(pp.Acks)
	}
	built, _ := build.Targets(buildDir(dir, c, r))
	swept := map[string]bool{}
	// Every parsed slice of this round, for the fleet-level verdict.
	var round []logs.Stats
	failed := 0
	for _, lg := range runLogs {
		st, err := logs.ParseFile(lg)
		if err != nil {
			continue
		}
		st.Target = targetOf(lg)
		swept[st.Target] = true
		round = append(round, st)
		for _, v := range []gate.Verdict{
			gate.Starvation(st, *floor, starveAcks),
			gate.SlowUnits(st),
			gate.UBSan(st, c.Name, accepted),
		} {
			if v.Failed {
				failed++
				fmt.Println(v)
			}
		}
	}
	var sweptList []string
	for t := range swept {
		sweptList = append(sweptList, t)
	}
	// WHAT THIS ROUND SAW, so absence can be judged over a series rather than
	// a single round -- and so the accept-list can shrink. A gate whose list
	// only ever grows becomes the table nobody reads.
	var seenUB []string
	for _, st := range round {
		for _, u := range st.UB {
			if u.Function != "" {
				seenUB = append(seenUB, u.Function)
			}
		}
	}
	if home, err := r.NeedHome(); err == nil {
		series := filepath.Join(home, "scripts", "ubsan-series.jsonl")
		var accTokens []string
		for _, a := range accepted {
			if gate.InScope(a, c.Name) {
				accTokens = append(accTokens, a.Function)
			}
		}
		if v := gate.UBSanWithdrawals(series, c.Name, accTokens, seenUB); len(v.Detail) > 0 {
			fmt.Println(v)
		}
		if err := gate.RecordUBSanRound(series, gate.UBSanRound{
			WS: c.Name, Log: "gate", Sites: seenUB,
		}); err != nil {
			fmt.Fprintf(os.Stderr, "pgfuzz: recording the ubsan round: %v\n", err)
		}
	}

	// The round as a whole: whether its numbers can be believed at all.
	// Starvation judges one target against a floor; this asks how many slices
	// reported anything, because a floor cannot be verified against a slice
	// that never said what it did.
	if v := gate.FinalStats(round, *minStats); v.Failed {
		failed++
		fmt.Println(v)
	}
	if v := gate.RoundComplete(sweptList, built); v.Failed {
		failed++
		fmt.Println(v)
	}

	if failed == 0 {
		fmt.Printf("all gates passed  %s  (%d logs, %d targets built)\n",
			c.Name, len(runLogs), len(built))
		return 0
	}
	fmt.Printf("\n%d gate failure(s)  %s\n", failed, c.Name)
	return 1
}

// targetOf names the target a log belongs to, from either layout.
func targetOf(path string) string {
	if d := filepath.Base(filepath.Dir(path)); strings.HasSuffix(d, "_fuzzer") {
		return d
	}
	n := strings.TrimSuffix(filepath.Base(path), ".log")
	return strings.TrimPrefix(n, "soak-")
}

type wsList []string

func (w *wsList) String() string     { return strings.Join(*w, ",") }
func (w *wsList) Set(v string) error { *w = append(*w, v); return nil }

// campaignProvenance is what the build in this campaign's own slug recorded.
//
// Read from the slug, never from the shared workspace: a sealed campaign that
// reused a build must still describe the build it ran, and BUILD-INFO.json in
// the campaign's build directory is the only place that fact is written down.
func campaignProvenance(slugDir, ws string) (sha string, pins map[string]string) {
	bi := archive.ReadBuildInfo(filepath.Join(
		campaign.BuildDir(slugDir, ws), "BUILD-INFO.json"))
	return bi.PGRefSHA, bi.Plugins
}

// campaignPatches names the workspace patch series with the hash of each file,
// so a sealed manifest says WHICH patch was applied and not merely that one
// was. A patch is part of the system under test; a run against a patched tree
// that does not record the patch is not reproducible.
func campaignPatches(c interface{ Get(string) string }) []string {
	var out []string
	for _, pf := range strings.Fields(c.Get("patch")) {
		out = append(out, filepath.Base(pf)+"@"+inventory.ShaFile(pf))
	}
	return out
}

func cmdCampaign(argv []string) int {
	fs := flag.NewFlagSet("campaign", flag.ExitOnError)
	var wss wsList
	fs.Var(&wss, "w", "workspace (repeatable)")
	slug := fs.String("slug", "", "campaign name")
	hours := fs.Float64("hours", 1, "how long to run")
	per := fs.Int("time", 600, "seconds per target")
	jobs := fs.Int("jobs", 1, "parallel jobs per target")
	par := fs.Int("parallel", 1, "workspaces sweeping at once")
	onDeadline := fs.String("on-deadline", "cut", "cut | finish-sweep | finish-round")
	maxOverrun := fs.Duration("max-overrun", 0, "cap on overrun (default: one sweep)")
	sealed := fs.Bool("sealed", false, "give the campaign its own corpus, so the slug can be reported and moved")
	rebuild := fs.Bool("rebuild", false, "rebuild even if the campaign already has a build")
	noBuild := fs.Bool("no-build", false, "refuse to build; use only what the campaign already has")
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	if err := fs.Parse(argv); err != nil || *slug == "" || len(wss) == 0 {
		fs.Usage()
		return 2
	}
	switch campaign.OnDeadline(*onDeadline) {
	case campaign.Cut, campaign.FinishSweep, campaign.FinishRound:
	default:
		fmt.Fprintln(os.Stderr, "pgfuzz: -on-deadline must be cut, finish-sweep or finish-round")
		return 2
	}

	r := paths.Resolve()
	slugDir := filepath.Join(r.Campaigns(), *slug)
	if err := os.MkdirAll(filepath.Join(slugDir, "ws"), 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
		return 2
	}

	// OPENED BEFORE THE BUILD PHASE. It used to be opened after, so for the
	// twenty minutes a five-workspace build takes there was no campaign.json:
	// `pgfuzz stop` found nothing, a PID lookup found nothing, and the TUI had
	// no campaign to show. A campaign has to be controllable from the moment it
	// starts, and the build phase is when it is least interruptible by hand.
	runID := campaign.RunID("go", time.Now())
	live, err := campaign.Open(r.Campaigns(), *slug, campaign.State{
		Slug: *slug, RunID: runID, PID: os.Getpid(),
		Started: time.Now().UTC().Format(time.RFC3339),
		Driver:  "go", Hours: fmt.Sprint(*hours),
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
		return 2
	}
	defer live.Close()
	// Declared BEFORE the build phase. The grid is drawn from the campaign's
	// declared workspaces, not from its series -- a workspace that has not
	// produced a slice yet still has a row, which is the only way the build
	// phase is visible at all.
	live.Entries([]string(wss))

	var entries []campaign.Entry
	var names []string
	var mentries []campaign.ManifestEntry
	for _, name := range wss {
		dir, c, _, err := openWS(name)
		if err != nil {
			fmt.Fprintf(os.Stderr, "pgfuzz: %s: %v\n", name, err)
			return 2
		}

		// THE CAMPAIGN OWNS ITS BUILDS. Not the workspace: a workspace build is
		// overwritten by the next build of that workspace, and after that the
		// campaign's results describe binaries that no longer exist, so a
		// coverage rerun measures something else under the campaign's name.
		// Held for the whole campaign. Two campaigns sharing a workspace
		// share its corpus and truncate each other's per-target logs, and
		// neither says so -- the numbers keep arriving and belong to no
		// single experiment.
		lk, err := wslock.Acquire(dir, "campaign "+*slug)
		if err != nil {
			fmt.Fprintf(os.Stderr, "pgfuzz: %s: %v\n", c.Name, err)
			return 2
		}
		defer lk.Release()

		// THE CONTAINERS GO WITH US. `docker run` is a client and the container is
		// a child of dockerd, so an interrupt takes down the client and leaves the
		// fuzzer running -- the stop command's own comment records "eighteen
		// containers kept fuzzing". Scoped to this process's own containers by the
		// pid in their name.
		defer func() {
			if n := fuzz.ReapOwn(); n > 0 {
				fmt.Fprintf(os.Stderr, "stopped %d container(s) started by this run\n", n)
			}
		}()

		if err := os.MkdirAll(campaign.WSDir(slugDir, c.Name), 0o755); err != nil {
			fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
			return 2
		}
		out := campaign.BuildDir(slugDir, c.Name)
		have, _ := build.Targets(out)
		switch {
		case len(have) > 0 && !*rebuild:
			fmt.Fprintf(os.Stderr, "==> %s: reusing the campaign's build (%d targets)\n",
				c.Name, len(have))
		case *noBuild:
			fmt.Fprintf(os.Stderr, "pgfuzz: %s: no build in %s and -no-build was given\n",
				c.Name, out)
			return 2
		default:
			if err := buildIntoCampaign(slugDir, c.Name, out, dir); err != nil {
				// LOUD, and recorded, but not fatal to the whole campaign.
				// One major whose plugins will not compile must not cost the
				// other four their two hours -- and a workspace that silently
				// vanished from a run is exactly what the manifest exists to
				// prevent, so it goes in with build_ok false and the reason.
				fmt.Fprintf(os.Stderr,
					"\npgfuzz: !! %s WILL NOT BE FUZZED: %v\n\n", c.Name, err)
				b, f := pluginOutcome(campaign.BuildLog(slugDir, c.Name))
				me := campaign.ManifestEntry{
					Workspace: c.Name, Ref: c.Ref,
					Sanitizer: c.Sanitizer, Engine: c.Get("engine"),
					Plugins: b, PluginsFail: f, BuildOK: false,
					Patches:     campaignPatches(c),
					OrioleDBSHA: workspaceOrioleSHA(r.WS, c.Name),
					Note:        "build failed; excluded from this campaign",
				}
				bsha, bpins := campaignProvenance(slugDir, c.Name)
				me.Provenance(bsha, c.Get("sha"), bpins)
				mentries = append(mentries, me)
				continue
			}
		}

		ts, err := build.Targets(out)
		ts = selectTargets(c, ts)
		if err != nil || len(ts) == 0 {
			fmt.Fprintf(os.Stderr, "pgfuzz: %s: nothing built\n", name)
			return 2
		}
		// SEALED decides whose corpus this is. Unsealed shares the workspace's,
		// which is right for a local run: the corpus is the accumulated value
		// of every campaign before it. Sealed takes its own copy, so nothing
		// outside can change it and the slug can be moved and re-measured.
		data := dir
		seeded := 0
		if *sealed {
			data = campaign.WSDir(slugDir, c.Name)
			linked, copied, err := campaign.SeedCorpus(
				campaign.CorpusDir(slugDir, c.Name), filepath.Join(dir, "corpus"))
			if err != nil {
				fmt.Fprintf(os.Stderr, "pgfuzz: %s: seeding the corpus: %v\n", c.Name, err)
				return 2
			}
			seeded = linked + copied
			fmt.Fprintf(os.Stderr, "==> %s: sealed corpus (%d linked, %d copied)\n",
				c.Name, linked, copied)
		}

		built, failed := pluginOutcome(campaign.BuildLog(slugDir, c.Name))
		me := campaign.ManifestEntry{
			Workspace: c.Name, Ref: c.Ref,
			Sanitizer: c.Sanitizer, Engine: c.Get("engine"), Key: c.Get("key"),
			Targets: ts, Plugins: built, PluginsFail: failed, BuildOK: true,
			Patches: campaignPatches(c), SeededInputs: seeded,
			OrioleDBSHA: workspaceOrioleSHA(r.WS, c.Name),
		}
		bsha, bpins := campaignProvenance(slugDir, c.Name)
		me.Provenance(bsha, c.Get("sha"), bpins)
		mentries = append(mentries, me)
		maxLen := 4096
		if v := c.Get("max_len"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				maxLen = n
			}
		}
		entries = append(entries, campaign.Entry{
			Name: c.Name, Dir: dir, Data: data, OutDir: out, Targets: ts,
			MaxLen: maxLen, San: c.Sanitizer,
		})
		names = append(names, c.Name)
	}

	if len(entries) == 0 {
		fmt.Fprintln(os.Stderr, "pgfuzz: no workspace built; nothing to fuzz")
		campaign.WriteManifest(slugDir, campaign.Manifest{
			Slug: *slug, Started: time.Now().UTC(), Entries: mentries})
		return 1
	}

	// The manifest is written BEFORE the rounds start. A campaign that is
	// killed mid-run must still say what it was built from -- that is the
	// whole point of the directory standing on its own.
	man := campaign.Manifest{
		Slug: *slug, Started: time.Now().UTC(),
		Hours: *hours, PerTarget: *per, Jobs: *jobs, Entries: mentries,
		Sealed: *sealed,
	}
	if pin, err := archive.ReadPin(r.Home); err == nil {
		man.OSSFuzz, man.BaseImage = pin.Commit, pin.BaseImage
	}
	if err := campaign.WriteManifest(slugDir, man); err != nil {
		fmt.Fprintf(os.Stderr, "pgfuzz: writing the manifest: %v\n", err)
		return 2
	}

	// NOT rewritten with the workspaces that built. The declared list is every
	// workspace the campaign was asked for, and a workspace whose build failed
	// has to keep its row -- drawn ×, which is a fact -- rather than vanish
	// from the grid as though it had never been asked for.
	_ = names
	live.MarkRunning()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	fmt.Fprintf(os.Stderr, "==> campaign %s  %d workspaces  %.2gh  %ds/target  on-deadline=%s\n",
		*slug, len(entries), *hours, *per, *onDeadline)
	err = campaign.Run(ctx, campaign.Config{
		Slug: *slug, RunID: runID, Hours: *hours, PerTarget: *per, Jobs: *jobs,
		Entries: entries, OnDeadline: campaign.OnDeadline(*onDeadline),
		Parallel:   *par,
		MaxOverrun: *maxOverrun,
		Series:     campaign.Series{Path: filepath.Join(r.Campaigns(), *slug, "series.jsonl")},
		Out:        os.Stderr,
		// From the RATCHET series, which is where new_units lives. A workspace
		// with no history contributes nothing and falls back to rotation.
		Productivity: productivity(r, entries),
		// THE GATES RUN, and they run in this order. The shell spliced
		// `ratchet check` then `ratchet update` into every workspace-round and
		// said why: updating first raises the floor to include the round being
		// judged, so nothing can ever regress. Without a caller the ratchet was
		// a gate nobody ran.
		AfterSweep: func(e campaign.Entry, round int, complete bool, notJudgeable string) {
			gateAfterSweep(r, e, round, *jobs, notJudgeable)
		},
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
		return 1
	}

	// THE STOP MARKER, which had a reader, a path helper and a line in the
	// bundle inventory, and no writer anywhere. Without it the final report's
	// "stopped at" is blank for every campaign this tool runs, and nothing
	// afterwards can say how big each corpus was when the numbers were taken
	// -- so a bundle cannot be checked against the corpus it was measured on.
	var counts []finalreport.CorpusCount
	for _, e := range entries {
		// Entry.Data already resolves this: the workspace for a local run,
		// the campaign's own directory for a sealed one.
		dir := filepath.Join(e.Data, "corpus")
		ents, _ := os.ReadDir(dir)
		for _, t := range ents {
			if !t.IsDir() {
				continue
			}
			// Measure, not Artifacts: Artifacts counts crash-, oom-,
			// timeout- and leak- files only, so a corpus of 2,285 inputs
			// recorded as 0 -- the marker's whole purpose is the input count.
			st := corpus.Measure(filepath.Join(dir, t.Name()))
			counts = append(counts, finalreport.CorpusCount{
				Workspace: e.Name, Target: t.Name(), Inputs: st.Files,
			})
		}
	}
	if err := finalreport.WriteStopMarker(
		finalreport.MarkerPath(r.WS), time.Now(), counts); err != nil {
		// Said, not swallowed: the report reads this file and reports nothing
		// when it is missing, which looks like a campaign that never stopped.
		fmt.Fprintf(os.Stderr, "pgfuzz: could not record the stop marker: %v\n", err)
	}

	fmt.Printf("campaign %s complete\n", *slug)
	return 0
}

func cmdReport(argv []string) int {
	fs := flag.NewFlagSet("report", flag.ExitOnError)
	slug := fs.String("slug", "", "campaign name")
	htmlOut := fs.String("html", "", "write a self-contained HTML report here")
	mdOut := fs.String("md", "", "write the same report as Markdown here")
	from := fs.String("from", "", "re-render an archived report's data.json instead of gathering")
	covWS := fs.String("cov", "", "coverage workspace to include")
	final := fs.Bool("final", false, "the campaign snapshot report")
	execSum := fs.Bool("exec", false, "the one-page summary")
	funnel := fs.String("funnel", "", "the run funnel for a campaign record file")
	record := fs.String("record", "", "render a campaign record file")
	against := fs.String("against", "", "compare -funnel against this record file")
	prefix := fs.String("prefix", "pg17-ext-all", "workspace prefix the snapshot covers")
	dataOut := fs.String("data", "", "write the gathered data here (default beside the report)")
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	if err := fs.Parse(argv); err != nil {
		fs.Usage()
		return 2
	}
	if *record != "" {
		return cmdCampaignRecord(*record, *against)
	}
	if *funnel != "" {
		return cmdFunnel(*funnel, *against)
	}
	if *execSum {
		return cmdExecReport(*prefix, *htmlOut)
	}
	if *final {
		return cmdFinalReport(*prefix, *htmlOut, *dataOut, *mdOut, *from)
	}
	if *slug == "" {
		fs.Usage()
		return 2
	}
	r := paths.Resolve()
	s := campaign.Series{Path: filepath.Join(r.Campaigns(), *slug, "series.jsonl")}

	if *htmlOut != "" || *mdOut != "" {
		return writeReport(r, *slug, s, *covWS, *htmlOut, *mdOut)
	}

	rows, err := s.Read()
	if err != nil {
		fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
		return 2
	}
	if len(rows) == 0 {
		fmt.Fprintln(os.Stderr, "pgfuzz: no slices recorded")
		return 2
	}

	type agg struct{ execs, newUnits, arts, slices, cov int }
	byWS := map[string]*agg{}
	rounds := map[int]bool{}
	var totalExecs, totalNew, totalArts int
	for _, row := range rows {
		a := byWS[row.Workspace]
		if a == nil {
			a = &agg{}
			byWS[row.Workspace] = a
		}
		a.execs += row.Execs
		a.newUnits += row.NewUnits
		a.arts += row.Artifacts
		a.slices++
		if row.Cov > a.cov {
			a.cov = row.Cov
		}
		rounds[row.Round] = true
		totalExecs += row.Execs
		totalNew += row.NewUnits
		totalArts += row.Artifacts
	}

	fmt.Printf("campaign %s\n", *slug)
	fmt.Printf("  %d slices  %d rounds  %d workspaces\n", len(rows), len(rounds), len(byWS))
	fmt.Printf("  %s executions  +%s new inputs  %d artifacts\n\n",
		comma(totalExecs), comma(totalNew), totalArts)
	fmt.Printf("  %-24s %6s %14s %10s %8s %8s\n", "WORKSPACE", "SLICES", "EXECS", "NEW", "ARTS", "COV")
	for _, name := range sortedNames(byWS) {
		a := byWS[name]
		fmt.Printf("  %-24s %6d %14s %10s %8d %8d\n",
			name, a.slices, comma(a.execs), comma(a.newUnits), a.arts, a.cov)
	}
	return 0
}

func sortedNames[T any](m map[string]T) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

func comma(n int) string {
	s := strconv.Itoa(n)
	if len(s) <= 3 {
		return s
	}
	var out []byte
	for i, c := range []byte(s) {
		if i > 0 && (len(s)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, c)
	}
	return string(out)
}

func cmdCoverage(argv []string) int {
	fs := flag.NewFlagSet("coverage", flag.ExitOnError)
	ws := fs.String("w", "", "coverage workspace")
	union := fs.Bool("union", true, "merge every per-target profile")
	measure := fs.Bool("measure", false, "replay each target's corpus and record its coverage")
	only := fs.String("t", "", "measure only this target")
	minFree := fs.Float64("min-free-gb", 60, "refuse to start below this much free space")
	stopFree := fs.Float64("stop-free-gb", 20, "kill the run if free space falls below this")
	timeout := fs.Duration("timeout", 60*time.Minute, "give up after this long")
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	if err := fs.Parse(argv); err != nil || *ws == "" || (!*union && !*measure) {
		fs.Usage()
		return 2
	}
	dir, c, r, err := openWS(*ws)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
		return 2
	}

	// MEASURE, which nothing in the port did. FindProfiles reads a layout only
	// the deleted shell created, so coverage was a view over leftovers that
	// would return nothing forever once they were pruned.
	if *measure {
		targets, _ := build.Targets(buildDir(dir, c, r))
		if *only != "" {
			targets = []string{*only}
		}
		if len(targets) == 0 {
			fmt.Fprintf(os.Stderr, "pgfuzz: nothing built in %s\n", dir)
			return 2
		}
		home, err := r.NeedHome()
		if err != nil {
			fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
			return 2
		}
		series := filepath.Join(home, "scripts", "coverage-series.jsonl")
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()

		failed := 0
		for _, t := range targets {
			sum, err := coverage.Measure(ctx, coverage.MeasureRequest{
				OSSFuzz: r.OSSFuzz(), Project: c.Project, Target: t,
				Corpus:    filepath.Join(dir, "corpus", t),
				Out:       buildDir(dir, c, r),
				Sanitizer: c.Sanitizer,
				MinFreeGB: *minFree, StopFreeGB: *stopFree,
				Stream: os.Stderr,
			})
			if err != nil {
				// Said out loud and counted. A target whose measurement was
				// refused must not read as a target with no coverage.
				fmt.Fprintf(os.Stderr, "  %-26s NOT RECORDED: %v\n", t, err)
				failed++
				continue
			}
			if err := coverage.RecordTarget(series, c.Name, sum); err != nil {
				fmt.Fprintf(os.Stderr, "  %-26s could not record: %v\n", t, err)
				failed++
				continue
			}
			fmt.Printf("  %-26s %d/%d lines (%.1f%%)\n",
				t, sum.Lines.Covered, sum.Lines.Count, sum.Lines.Percent)
		}
		if failed > 0 {
			fmt.Fprintf(os.Stderr, "\n%d target(s) produced no usable measurement\n", failed)
			return 1
		}
		if !*union {
			return 0
		}
	}
	profiles, err := coverage.FindProfiles(r.WS)
	if err != nil || len(profiles) == 0 {
		fmt.Fprintf(os.Stderr, "pgfuzz: no per-target profiles under %s\n", r.WS)
		return 2
	}
	fmt.Fprintf(os.Stderr, "==> merging %d per-target profiles\n", len(profiles))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	sum, err := coverage.Union(ctx, coverage.UnionRequest{
		Out:      buildDir(dir, c, r),
		Profiles: profiles,
		Stage:    filepath.Join(dir, ".union"),
		Timeout:  *timeout,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
		return 1
	}
	fmt.Printf("\nALL %d TARGETS COMBINED, lines counted once\n\n", sum.Targets)
	for _, row := range []struct {
		name string
		c    coverage.Counted
	}{
		{"lines", sum.Lines}, {"functions", sum.Functions},
		{"regions", sum.Regions}, {"branches", sum.Branches},
	} {
		if row.c.Count == 0 {
			continue
		}
		fmt.Printf("  %-10s %12s / %-12s %6.2f%%\n", row.name,
			comma(row.c.Covered), comma(row.c.Count), row.c.Pct())
	}
	fmt.Printf("  %-10s %12s / %-12s %6.2f%%\n", "files",
		comma(sum.FilesSeen), comma(sum.Files),
		100*float64(sum.FilesSeen)/float64(max(sum.Files, 1)))
	return 0
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func cmdRatchet(argv []string) int {
	fs := flag.NewFlagSet("ratchet", flag.ExitOnError)
	ws := fs.String("w", "", "workspace")
	update := fs.Bool("update", false, "raise floors that were beaten")
	basePath := fs.String("baseline", "", "baseline json (default: the profile's)")
	profile := fs.String("profile", "main", "an isolated record: baseline, series and history together")
	jobs := fs.Int("jobs", 1, "the job count this round ran at")
	round := fs.Int("round", -1, "judge this round; default the newest by mtime")
	show := fs.Bool("show", false, "print the baseline")
	cusum := fs.Bool("cusum", false, "sustained downward shift, which the record's skirt misses")
	activity := fs.Bool("activity", false, "what the floors did -- the upward half of the ratchet")
	dist := fs.Bool("distribution", false, "where observations sit relative to their floors")
	variance := fs.Bool("variance", false, "round-over-round spread, to set the tolerance on evidence")
	reseed := fs.String("reseed", "", "recompute this target's floors from qualifying rounds")
	reason := fs.String("reason", "", "why the floors are being recomputed; required by -reseed")
	since := fs.String("since", "", "ignore records older than this ISO prefix")
	top := fs.Int("top", 8, "how many of the largest raises to list")
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	if err := fs.Parse(argv); err != nil {
		fs.Usage()
		return 2
	}
	// The analyses read the SERIES and the HISTORY, not one round's logs, so
	// they need no workspace -- and requiring one would make "how has every
	// floor behaved" unaskable.
	if *reseed != "" {
		return cmdReseed(*reseed, *since, *reason, *basePath, *profile)
	}
	if *show || *cusum || *activity || *dist || *variance {
		return ratchetAnalysis(*ws, *basePath, *profile, ratchetModes{
			Show: *show, Cusum: *cusum, Activity: *activity,
			Distribution: *dist, Variance: *variance, Since: *since, Top: *top,
		})
	}
	if *ws == "" {
		fs.Usage()
		return 2
	}
	dir, c, r, err := openWS(*ws)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
		return 2
	}
	pp, err := profilePaths(r, *profile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
		return 2
	}
	if *basePath == "" {
		*basePath = pp.Baseline
	}
	b, err := pp.LoadBaseline(*basePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
		return 2
	}

	// THE NEWEST EVIDENCE, whichever form it is in.
	//
	// A sweep log holds every target of a round in one file; the campaign
	// driver writes one log per target under artifacts/. Both are real, and
	// preferring the FORM rather than the FRESHNESS judged a campaign that had
	// just finished using a sweep log from ten days earlier -- 21 targets
	// reported as judged, on a run that did not happen that day. The gate
	// whose whole job is catching a silent regression silently graded the
	// wrong run.
	//
	// So: take whichever is newer. An explicit -round always wins, because
	// naming a round is asking for that round.
	var obs []ratchet.Observation
	var readFrom, readFromPath string
	regime := ratchet.Regime(*jobs)
	sweep := ratchet.SweepLog(dir, *round)
	perTarget := gatherRunLogs(dir)
	if *round < 0 && sweep != "" && len(perTarget) > 0 && newest(perTarget).After(mtime(sweep)) {
		sweep = ""
	}
	if lg := sweep; lg != "" {
		per, err := logs.ParseSweep(lg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
			return 2
		}
		readFrom, readFromPath = filepath.Base(lg), lg
		// THE REGIME COMES FROM THE LOG, not from a flag.
		//
		// A caller who forgets -jobs would otherwise have every floor compared
		// against the wrong regime, silently: the round ran with four workers
		// and is judged as though it ran with one. The log records what was
		// actually launched, so ask it.
		if r, err := logs.ParseRegime(lg); err == nil {
			regime = ratchet.Regime(r.Jobs)
		}
		for t, st := range per {
			if st.Execs == 0 {
				continue
			}
			obs = append(obs, ratchet.Observation{
				Target: t, Execs: st.Execs, Rate: st.Rate,
				NewUnits: st.NewUnits, Regime: regime,
			})
		}
	} else {
		// One log per target. Only the NEWEST per target: the directory keeps
		// every run, and summing them would credit this slice with every
		// execution the target has ever done.
		logsFound := newestPerTarget(perTarget)
		// THE REGIME COMES FROM THE LOG here too. These logs carry the
		// invocation just as a sweep log does, and taking it from the -jobs
		// flag instead reported a two-worker campaign as jobs=1 -- comparing
		// every floor against a regime the run was never in.
		if len(logsFound) > 0 {
			if reg, err := logs.ParseRegime(logsFound[0]); err == nil {
				regime = ratchet.Regime(reg.Jobs)
			}
		}
		for _, lg := range logsFound {
			st, err := logs.ParseFile(lg)
			if err != nil || st.Execs == 0 {
				continue
			}
			readFrom, readFromPath = "per-target run logs", lg
			obs = append(obs, ratchet.Observation{
				Target: targetOf(lg), Execs: st.Execs, Rate: st.Rate,
				NewUnits: st.NewUnits, Regime: regime,
			})
		}
	}
	if len(obs) == 0 {
		// NOT a pass. A gate that finds nothing to check and exits 0 is
		// indistinguishable from a gate that checked everything and approved
		// it, and that is the direction that gets believed.
		fmt.Fprintf(os.Stderr, "pgfuzz: no round log under %s -- nothing was checked,\n"+
			"  which is not the same as nothing being wrong\n", dir)
		return 2
	}
	sort.Slice(obs, func(i, j int) bool { return obs[i].Target < obs[j].Target })
	if readFrom != "" {
		fmt.Printf("  log: %s   tolerance: %d%% of floor\n", readFrom, int(b.Tol()*100))
		fmt.Printf("  regime is %s\n", regime)
	}
	if len(obs) == 0 {
		fmt.Fprintln(os.Stderr, "pgfuzz: no per-target execution counts")
		return 2
	}

	if *update {
		// The whole read-modify-write under one lock. Thirty-two slices finish
		// concurrently, and an unlocked update loses whichever floor was
		// raised first -- silently, because the other write succeeds.
		var res ratchet.UpdateResult
		err := ratchet.WithLock(*basePath, func() error {
			fresh, err := pp.LoadBaseline(*basePath)
			if err != nil {
				return err
			}
			// Re-read INSIDE the lock. The copy loaded before it was taken may
			// already be stale.
			res = fresh.Update(c.Name, obs)
			return fresh.Save(*basePath)
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
			return 2
		}
		for _, sw := range res.Switched {
			fmt.Printf("  archived  %-26s %s earned at %s -- not comparable to %s\n",
				sw.Target, comma(sw.Value), sw.From, regime)
		}
		recordRound(r, pp, dir, c.Name, *round, readFromPath, obs, res)
		fmt.Printf("  %s: %d floor(s) recorded, %d raised   |   rate: %d recorded, %d raised\n",
			c.Name, res.Added, res.Raised, res.RateAdded, res.RateRaised)
		acks, _ := ratchet.LoadAcks(pp.Acks)
		// Against the floors as JUST RAISED, not the pre-lock copy: a target
		// whose floor rose in this very update was otherwise measured against
		// the lower old one, so "no longer starves" was reported too eagerly.
		after, err := pp.LoadBaseline(*basePath)
		if err != nil {
			after = b
		}
		for _, t := range ratchet.Expired(obs, after.Floors[c.Name], acks, after.Tol()) {
			fmt.Printf("  expired   %s no longer starves -- remove its row from known-starved.tsv\n", t)
		}
		return 0
	}

	// THE ACKNOWLEDGEMENT LIST, which this passed as nil.
	//
	// ratchet.Check supports it and there is a passing test for the
	// Acknowledged outcome; the line below is the only caller, so that outcome
	// was unreachable and the `known` branch a few lines down was dead. A
	// target somebody wrote a row for would regress the round every round,
	// forever -- which is precisely what teaches people to ignore a gate.
	// Latent only because the file has no data rows yet: the first row anyone
	// added would have done nothing.
	acks, err := ratchet.LoadAcks(pp.Acks)
	if err != nil && !os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "pgfuzz: reading the acknowledgement list: %v\n", err)
		return 2
	}
	rep := ratchet.Check(b, c.Name, obs, acks)
	if rep.Seeded {
		// Not a pass, and said so: a floor cannot be regressed from before it
		// exists, and silence here makes a workspace with no history look
		// identical to a healthy one.
		fmt.Printf("ratchet %s: no baseline yet -- run with -update to seed it\n", c.Name)
		fmt.Println("  (this is not a pass)")
		return 2
	}
	var regressed, skipped, fresh, execSkipped int
	// The acknowledged rows are printed too. An acknowledgement is a decision
	// made in a commit, not a reason to go quiet: a target that is silently
	// exempt is indistinguishable from one that is passing.
	for _, j := range rep.Judged {
		if j.ExecFloorSkipped {
			execSkipped++
		}
		if j.Outcome == ratchet.Acknowledged {
			fmt.Printf("  known     %-26s %s vs floor %s -- %s\n",
				j.Target, comma(j.Observed), comma(j.Floor), j.Note)
		}
		switch j.Outcome {
		case ratchet.Regressed:
			regressed++
			// Say WHICH floor decided it. The rate and the exec floor differ
			// by orders of magnitude, so a bare number cannot be checked
			// against the baseline by anyone reading the log later.
			if j.ByRate {
				fmt.Printf("  REGRESSED %-26s %12.2f of a %.1f rate floor (%.1f%%)\n",
					j.Target, j.Rate, j.RateFloor, 100*j.Rate/j.RateFloor)
			} else {
				fmt.Printf("  REGRESSED %-26s %12s of a %s floor (%.1f%%)\n",
					j.Target, comma(j.Observed), comma(j.Floor),
					100*float64(j.Observed)/float64(j.Floor))
			}
		case ratchet.Incomparable:
			skipped++
			// "an unrecorded regime" rather than an empty string: a blank
			// there reads as a formatting bug, not as the legacy floor it is.
			earned := j.Earned
			if earned == "" {
				earned = "an unrecorded regime"
			}
			fmt.Printf("  skipped   %-26s floor %s earned at %s, this run %s\n",
				j.Target, comma(j.Floor), earned, j.Regime)
		case ratchet.NoFloor:
			fresh++
		}
	}
	if execSkipped > 0 {
		// Said out loud, because it is a coverage loss: those floors are not
		// protecting anything this round, and only the rate floor beside them
		// is. The next update stamps them with the regime that produced them.
		fmt.Printf("  %d execution floor(s) not comparable at %s -- judged on their rate floors instead\n",
			execSkipped, obs[0].Regime)
	}
	fmt.Printf("ratchet %s: %d judged, %d regressed, %d incomparable, %d new\n",
		c.Name, len(rep.Judged), regressed, skipped, fresh)
	if regressed > 0 {
		return 1
	}
	return 0
}

func cmdTUI(argv []string) int {
	fs := flag.NewFlagSet("tui", flag.ExitOnError)
	slug := fs.String("slug", "", "campaign name or a path to one; default: where you are standing")
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	if err := fs.Parse(argv); err != nil {
		return 2
	}
	r := paths.Resolve()
	// A bare positional works too: `pgfuzz tui <slug-or-path>` is what anyone
	// tab-completing a directory will type.
	if *slug == "" && fs.NArg() > 0 {
		*slug = fs.Arg(0)
	}
	{
		var err error
		*slug, err = resolveCampaign(*slug, r)
		if err != nil {
			fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
			return 2
		}
	}

	// Not a terminal: print one frame and stop, rather than fighting a pipe.
	// `pgfuzz tui | head` should show the dashboard, not escape codes.
	if fi, err := os.Stdout.Stat(); err == nil && fi.Mode()&os.ModeCharDevice == 0 {
		m := tui.LoadWithPanels(r.Campaigns(), *slug, r.Home, r.WS)
		s := term.Screen{Plain: true}
		tui.Draw(&s, m, tui.Grid, 0, 40, 200)
		s.Flush(os.Stdout)
		fmt.Println()
		return 0
	}

	st, err := term.MakeRaw(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
		return 2
	}
	// Restore on every path: a process that exits without it leaves the shell
	// with no echo, which looks exactly like a hung terminal.
	defer st.Restore()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Stdout.WriteString(term.EnterAlt)
	defer os.Stdout.WriteString(term.LeaveAlt)

	view, sel := tui.Grid, 0
	var screen term.Screen
	buf := make([]byte, 8)
	tick := time.NewTicker(tui.Interval)
	defer tick.Stop()

	draw := func() {
		m := tui.LoadWithPanels(r.Campaigns(), *slug, r.Home, r.WS)
		if sel >= len(m.Rows) {
			sel = len(m.Rows) - 1
		}
		if sel < 0 {
			sel = 0
		}
		rows, cols := term.Size(os.Stdout)
		tui.Draw(&screen, m, view, sel, rows, cols)
		screen.Flush(os.Stdout)
	}
	draw()

	for {
		select {
		case <-ctx.Done():
			return 0
		case <-tick.C:
			draw()
		default:
		}
		n, _ := os.Stdin.Read(buf)
		if n == 0 {
			continue
		}
		switch buf[0] {
		case 'q', 'Q', 27:
			if buf[0] == 27 && n >= 3 && buf[1] == '[' {
				// An arrow key, not escape: they share a prefix, and treating
				// every escape as quit makes the arrows exit the program.
				switch buf[2] {
				case 'A':
					sel--
				case 'B':
					sel++
				}
				draw()
				continue
			}
			if view != tui.Grid {
				view = tui.Grid
				draw()
				continue
			}
			return 0
		case 'd', 'D':
			view = tui.Detail
			draw()
		case 'g', 'G':
			view = tui.Grid
			draw()
		case 'k':
			sel--
			draw()
		case 'j':
			sel++
			draw()
		}
	}
}

// resolveCampaign turns what is natural to type into a slug.
//
// THERE IS NO "NEWEST CAMPAIGN" RULE. An earlier version of this scanned the
// tree and took whichever directory looked freshest, which chose a campaign
// that had ended in August over the one fuzzing at that moment -- and then
// reported it as not running, which was true of the campaign it picked and
// useless to the person asking. You say which one, or you stand in it.
//
// Accepts:
//
//	pg17-ext-all                       the slug itself
//	~/pgfuzz/campaigns/pg17-ext-all    its directory
//	.../pg17-ext-all/live              or anything inside it
//	.../<slug>-<stamp>-<cfg8>            a sealed archive
//	~/pgfuzz/pg17-ext-all-und          a workspace of that campaign
//	(nothing)                            wherever you are standing
func resolveCampaign(arg string, r paths.Roots) (string, error) {
	if arg == "" {
		wd, err := os.Getwd()
		if err != nil {
			return "", fmt.Errorf("no campaign named, and the working directory is unreadable")
		}
		if slug := slugFromPath(wd, r); slug != "" {
			return slug, nil
		}
		return "", fmt.Errorf("no campaign named, and %s is not inside one.\n"+
			"  Pass -slug NAME, a path under %s, or cd into a campaign or workspace.",
			wd, r.Campaigns())
	}
	if st, err := os.Stat(arg); err == nil && st.IsDir() {
		if slug := slugFromPath(arg, r); slug != "" {
			return slug, nil
		}
	}
	// A bare name. Only accepted if the directory actually exists -- otherwise
	// a typo resolves to "no such campaign" somewhere far away, or worse to a
	// different one.
	name := filepath.Base(strings.TrimRight(arg, string(os.PathSeparator)))
	if st, err := os.Stat(filepath.Join(r.Campaigns(), name)); err == nil && st.IsDir() {
		return name, nil
	}
	return "", fmt.Errorf("no campaign %q under %s", arg, r.Campaigns())
}

var reWSSuffix = regexp.MustCompile(`-(add|und|cov|asan|sfz|nocassert)$`)

// slugFromPath is the campaign a directory implies, or "".
//
// Two shapes, both real places to point at: the campaign tree, and a workspace
// of that campaign. A workspace is identified by its workspace.conf rather
// than by its name, so an unrelated directory cannot masquerade as one.
func slugFromPath(path string, r paths.Roots) string {
	cwd, err := filepath.EvalSymlinks(path)
	if err != nil {
		return ""
	}
	if camp, err := filepath.EvalSymlinks(r.Campaigns()); err == nil {
		if cwd == camp {
			return ""
		}
		if rest, ok := strings.CutPrefix(cwd, camp+string(os.PathSeparator)); ok {
			if first := strings.Split(rest, string(os.PathSeparator))[0]; first != "" {
				return first
			}
			return ""
		}
	}
	root, err := filepath.EvalSymlinks(r.WS)
	if err != nil {
		return ""
	}
	rest, ok := strings.CutPrefix(cwd, root+string(os.PathSeparator))
	if !ok {
		return ""
	}
	first := strings.Split(rest, string(os.PathSeparator))[0]
	if _, err := os.Stat(filepath.Join(root, first, "workspace.conf")); err != nil {
		return ""
	}
	return reWSSuffix.ReplaceAllString(first, "")
}

// writeReport renders a campaign's report, as HTML, as Markdown, or both.
//
// ONE GATHER for however many documents are asked for. Two reports of one
// campaign assembled from two readings of the record is how they come to
// disagree, which has happened here three times already.
func writeReport(r paths.Roots, slug string, s campaign.Series, covWS, out, mdPath string) int {
	var cov *coverage.Summary
	if covWS != "" {
		dir, c, _, err := openWS(covWS)
		if err == nil {
			profiles, _ := coverage.FindProfiles(r.WS)
			if len(profiles) > 0 {
				ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
				defer stop()
				sum, err := coverage.Union(ctx, coverage.UnionRequest{
					Out:      buildDir(dir, c, r),
					Profiles: profiles,
					Stage:    filepath.Join(dir, ".union"),
					Timeout:  60 * time.Minute,
				})
				if err == nil {
					cov = &sum
				} else {
					// Said, not swallowed: a report that quietly omits
					// coverage looks like a campaign that measured none.
					fmt.Fprintf(os.Stderr, "pgfuzz: coverage omitted: %v\n", err)
				}
			}
		}
	}

	d, err := report.Gather(slug, s, filepath.Join(r.WS, "FINDINGS"), cov)
	// WHAT WAS UNDER TEST comes from the campaign's own sealed manifest.
	// Absent is not an error: `report -final` and the older slugs predate it,
	// and a missing section is honest where an empty one would read as "no
	// patches, no plugins, unknown commit".
	if m, merr := campaign.ReadManifest(filepath.Join(r.WS, "campaigns", slug)); merr == nil {
		d.WithManifest(m)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
		return 2
	}
	emit := func(path string, render func(io.Writer) error) int {
		f, err := os.Create(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
			return 2
		}
		defer f.Close()
		if err := render(f); err != nil {
			fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
			return 1
		}
		fi, _ := f.Stat()
		fmt.Printf("%s  %s bytes  %d findings", path, comma(int(fi.Size())), len(d.Findings))
		if cov != nil {
			fmt.Printf("  %.2f%% lines", cov.Lines.Pct())
		}
		fmt.Println()
		return 0
	}

	if out != "" {
		if code := emit(out, func(w io.Writer) error { return report.Render(w, d) }); code != 0 {
			return code
		}
	}
	if mdPath != "" {
		if code := emit(mdPath, func(w io.Writer) error { return report.RenderMarkdown(w, d) }); code != 0 {
			return code
		}
	}
	return 0
}

func cmdCensus(argv []string) int {
	fs := flag.NewFlagSet("census", flag.ExitOnError)
	var wss wsList
	fs.Var(&wss, "w", "workspace (repeatable; default: every one with logs)")
	out := fs.String("o", "", "write census/signatures.json under this directory")
	summary := fs.Bool("summary", false, "also write SUMMARY.md beside it")
	name := fs.String("name", "", "campaign name for the summary heading")
	since := fs.String("since", "", "ignore logs older than this (2026-08-31)")
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	if err := fs.Parse(argv); err != nil || *out == "" {
		fs.Usage()
		return 2
	}
	r := paths.Resolve()
	if len(wss) == 0 {
		ents, _ := os.ReadDir(r.WS)
		for _, e := range ents {
			if !e.IsDir() {
				continue
			}
			if m := gatherRunLogs(filepath.Join(r.WS, e.Name())); len(m) > 0 {
				wss = append(wss, e.Name())
			}
		}
	}
	var cutoff time.Time
	if *since != "" {
		t, err := time.Parse("2006-01-02", *since)
		if err != nil {
			fmt.Fprintf(os.Stderr, "pgfuzz: cannot parse -since %q\n", *since)
			return 2
		}
		cutoff = t
	}

	b := census.New()
	var logsRead int
	for _, ws := range wss {
		dir := filepath.Join(r.WS, ws)
		var files []string
		// Both layouts: one log per target (soak, and the Go runner's
		// artifacts/<target>/run-*.log) and one per round holding all of them
		// (the matrix driver's sweep-round*.log).
		for _, pat := range []string{
			"soak-*_fuzzer.log", "soak-*_fuzzer.log.gz",
			"artifacts/*/run-*.log", "artifacts/*/run-*.log.gz",
			"sweep-round*.log", "sweep-round*.log.gz",
		} {
			m, _ := filepath.Glob(filepath.Join(dir, pat))
			files = append(files, m...)
		}
		for _, p := range files {
			if !cutoff.IsZero() {
				if fi, err := os.Stat(p); err == nil && fi.ModTime().Before(cutoff) {
					continue
				}
			}
			f, rc, err := openMaybeGzip(p)
			if err != nil {
				continue
			}
			// Streamed: these logs run to gigabytes and reading one whole is
			// how a census becomes an out-of-memory kill.
			if strings.HasPrefix(filepath.Base(p), "sweep-round") {
				err = b.AddReader(ws, rc)
			} else {
				err = b.AddReaderAs(ws, targetOf(p), rc)
			}
			closeAll(rc, f)
			// Executed units, from the same file. A signature list cannot say
			// whether a silent target was quiet or dead.
			if f2, rc2, e := openMaybeGzip(p); e == nil {
				if raw, e := io.ReadAll(rc2); e == nil {
					b.CountUnits(ws, targetOf(p), string(raw))
				}
				closeAll(rc2, f2)
			}
			if err != nil {
				fmt.Fprintf(os.Stderr, "pgfuzz: %s: %v\n", filepath.Base(p), err)
			}
			logsRead++
		}
	}
	if logsRead == 0 {
		fmt.Fprintln(os.Stderr, "pgfuzz: no logs matched")
		return 2
	}
	// THE SANITIZER COMES FROM THE CONFIG. Deriving it from the workspace
	// name answers "other" for every workspace that does not use the -add /
	// -und suffix, which is half of them here and all of the ones any recent
	// campaign made.
	known := map[string]string{}
	for _, ws := range wss {
		if _, c, _, err := openWS(ws); err == nil {
			known[ws] = c.Sanitizer
		}
	}
	if err := b.Write(*out, known); err != nil {
		fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
		return 2
	}
	rows := b.Rows()
	census.Annotate(rows, known)
	var orioleOnly, inOriole int
	for _, row := range rows {
		if row.OrioleOnly {
			orioleOnly++
		}
		if row.InOrioleDB {
			inOriole++
		}
	}
	fmt.Printf("%d signatures from %d logs across %d workspaces -> %s/census/signatures.json\n",
		len(rows), logsRead, len(wss), *out)
	fmt.Printf("  %d seen only on oriole workspaces, %d failing inside OrioleDB's own tree\n",
		orioleOnly, inOriole)

	if *summary {
		// The workspace's OWN artifacts, counted. Passing an empty map made
		// the document say "artifacts kept: 0" for a workspace holding
		// hundreds -- a number that reads as "this campaign found nothing"
		// when what it meant was "this command copies nothing".
		arts := map[[2]string]int{}
		total := 0
		for _, ws := range wss {
			dir := filepath.Join(r.WS, ws, "artifacts")
			ents, _ := os.ReadDir(dir)
			for _, e := range ents {
				if !e.IsDir() {
					continue
				}
				n := len(corpus.Artifacts(filepath.Join(dir, e.Name())))
				if n > 0 {
					arts[[2]string{ws, e.Name()}] = n
					total += n
				}
			}
		}
		live := census.LivenessRows(b.Units(), arts, wss)
		f, err := os.Create(filepath.Join(*out, "SUMMARY.md"))
		if err != nil {
			fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
			return 2
		}
		defer f.Close()
		n := *name
		if n == "" {
			n = filepath.Base(*out)
		}
		// Build provenance, so a signature belongs to a TREE rather than to a
		// workspace name. Most of these refs move between campaigns, so the
		// name alone cannot be rechecked against anything.
		var prov []census.Build
		for _, ws := range wss {
			bi := archive.BuildInfoOf(r.OSSFuzz(), ws)
			if bi.PGRefSHA == "" {
				continue
			}
			prov = append(prov, census.Build{
				Workspace: ws, Ref: workspaceRef(r.WS, ws), Sanitizer: bi.Sanitizer,
				// From the CONF: BUILD-INFO's orioledb field is a bool saying
				// whether this is an OrioleDB build, never the commit.
				PGSHA: bi.PGRefSHA, OrioleDBSHA: workspaceOrioleSHA(r.WS, ws),
				// The patches a workspace applies live in its conf, not in
				// the build output.
				Patches: workspacePatches(r.WS, ws),
			})
		}
		census.WriteSummary(f, census.SummaryInput{
			Name: n, Workspaces: wss, NLogs: logsRead, Rows: rows, Live: live,
			Artifacts: total, Provenance: prov,
		})
		fmt.Printf("  wrote %s/SUMMARY.md\n", *out)
		var dead []string
		for _, r := range live {
			if r.ExecutedUnits == 0 && r.WSSeen > 0 {
				dead = append(dead, r.Target)
			}
		}
		if len(dead) > 0 {
			// Not buried in the document: a target that executed nothing is
			// the finding, and it files no crashes to announce itself.
			fmt.Printf("  %d target(s) executed NOTHING: %s\n",
				len(dead), strings.Join(dead, ", "))
		}
	}
	return 0
}

func cmdCorpus(argv []string) int {
	fs := flag.NewFlagSet("corpus", flag.ExitOnError)
	ws := fs.String("w", "", "workspace")
	repair := fs.Bool("repair", false, "make unreadable entries readable again")
	seedFrom := fs.String("seed-from", "", "copy inputs from this workspace")
	seedFromSrc := fs.String("seed-from-source", "", "generate seeds from a PostgreSQL source tree")
	extraGlobs := fs.String("extra-globs", "", "also take statements from these globs under the source tree")
	minimize := fs.Bool("minimize", false, "merge each corpus down to one input per coverage feature")
	autocap := fs.Bool("autocap", false, "bound each corpus so replay cannot eat the slice")
	tuneBudget := fs.Bool("tune-budget", false, "also adjust per-target budgets from discovery rate")
	apply := fs.Bool("apply", false, "actually cap; without it this only reports")
	capLog := fs.String("log", "", "sweep log to read (default: the newest)")
	fraction := fs.Float64("fraction", 0.33, "max share of the budget replay may consume")
	warnFraction := fs.Float64("warn-fraction", 0.66, "cap before a target locks, at this share")
	capFloor := fs.Int("floor", 500, "never cap below this many inputs")
	capAll := fs.Bool("all", false, "consider every target, however small its replay")
	capN := fs.Int("cap", 0, "after merging, keep at most N inputs (heuristic: smallest first)")
	capOnly := fs.Bool("cap-only", false, "apply the cap without re-merging")
	maxLen := fs.Int("max-len", 4096, "merge -max_len, and the size above which inputs are archived")
	rss := fs.Int("rss", 2560, "merge -rss_limit_mb")
	var only wsList
	fs.Var(&only, "t", "target to minimize; repeatable, default every target")
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
	root := filepath.Join(dir, "corpus")

	if *seedFrom != "" {
		srcDir, _, _, err := openWS(*seedFrom)
		if err != nil {
			fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
			return 2
		}
		if srcDir == dir {
			fmt.Fprintln(os.Stderr, "pgfuzz: refusing to seed a workspace from itself")
			return 2
		}
		// Repair the SOURCE first: seeding from a corpus half of which cannot
		// be read copies half a corpus and reports success.
		if n, _ := corpus.Repair(filepath.Join(srcDir, "corpus")); n > 0 {
			fmt.Fprintf(os.Stderr, "  repaired %d unreadable entries in %s first\n", n, *seedFrom)
		}
		copied, skipped, err := corpus.Seed(filepath.Join(srcDir, "corpus"), root)
		if err != nil {
			fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
			return 2
		}
		fmt.Printf("seeded %s from %s: +%s inputs, %s already present\n",
			c.Name, *seedFrom, comma(copied), comma(skipped))
		return 0
	}

	if *seedFromSrc != "" {
		// THE WORKSPACE'S OWN GLOBS, when the flag does not override them.
		//
		// corpus_globs= was the fourth config key the port recorded and never
		// read -- after plugins=, patch= and preload=. It exists because a
		// workspace can fuzz a 265-file patch for eleven hours and touch none
		// of it: the patch ships its own regression SQL, and without that SQL
		// in the seed corpus nothing ever reaches the code it added.
		globs := *extraGlobs
		if globs == "" {
			globs = c.Get("corpus_globs")
			if globs != "" {
				fmt.Printf("  corpus_globs from the workspace: %s\n", globs)
			}
		}
		n, err := seedcorpus.Generate(*seedFromSrc, root, globs, os.Stdout)
		if err != nil {
			fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
			return 2
		}
		_ = n
		return 0
	}
	if *autocap {
		return corpusAutocap(dir, c.Name, buildDir(dir, c, r), root, *capLog,
			corpus.AutocapOptions{
				Fraction: *fraction, WarnFraction: *warnFraction,
				Floor: *capFloor, All: *capAll, Skip: setOf(only),
			}, *tuneBudget, *apply)
	}
	if *minimize || *capOnly {
		return corpusMinimize(dir, buildDir(dir, c, r), root, []string(only), corpus.MinOptions{
			MaxLen: *maxLen, RSS: *rss, Cap: *capN, CapOnly: *capOnly,
		})
	}

	if *repair {
		n, err := corpus.Repair(root)
		if err != nil {
			fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
			return 2
		}
		fmt.Printf("repaired %s entries in %s\n", comma(n), c.Name)
		return 0
	}

	ents, _ := os.ReadDir(root)
	var total corpus.Stats
	fmt.Printf("  %-28s %10s %10s %12s\n", "TARGET", "INPUTS", "UNREADABLE", "SIZE")
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		st := corpus.Measure(filepath.Join(root, e.Name()))
		total.Files += st.Files
		total.Bytes += st.Bytes
		total.Unreadable += st.Unreadable
		mark := ""
		if st.Unreadable > 0 {
			mark = " <- run -repair"
		}
		fmt.Printf("  %-28s %10s %10d %12s%s\n",
			e.Name(), comma(st.Files), st.Unreadable, corpus.Human(st.Bytes), mark)
	}
	fmt.Printf("  %-28s %10s %10d %12s\n", "total", comma(total.Files),
		total.Unreadable, corpus.Human(total.Bytes))
	if total.Unreadable > 0 {
		// Not a footnote: an unreadable corpus reads as a small one, and a
		// small corpus reads as a target that has found nothing.
		fmt.Printf("\n  %d entries cannot be read. Until they are repaired every\n", total.Unreadable)
		fmt.Printf("  measurement over this corpus is an undercount.\n")
		return 1
	}
	_ = r
	return 0
}

func cmdWS(argv []string) int {
	fs := flag.NewFlagSet("ws", flag.ExitOnError)
	newName := fs.String("new", "", "create a workspace with this name")
	ref := fs.String("ref", "", "git ref for a new workspace")
	flavor := fs.String("flavor", "postgres", "postgres | orioledb")
	san := fs.String("sanitizer", "address", "address | undefined | coverage")
	plugins := fs.String("plugins", "", "plugins for a new workspace")
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	if err := fs.Parse(argv); err != nil {
		return 2
	}
	r := paths.Resolve()

	if *newName != "" {
		if *ref == "" {
			fmt.Fprintln(os.Stderr, "pgfuzz: -new needs -ref")
			return 2
		}
		dir := r.Workspace(*newName)
		if fileExists(filepath.Join(dir, "workspace.conf")) {
			// Never silently: a workspace.conf is the experiment, and
			// overwriting one makes every result already recorded against it
			// unattributable.
			fmt.Fprintf(os.Stderr, "pgfuzz: %s already exists\n", dir)
			return 2
		}
		if err := os.MkdirAll(dir, 0o755); err != nil {
			fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
			return 2
		}
		// A SLICE, not a map: map iteration is randomised, so the keys came
		// out in a different order in every workspace created, and two confs
		// that say the same thing did not diff as the same thing.
		//
		// targets= is written empty and MEANT: it is the key that says which
		// targets to run when you ask for all, and empty means every built
		// one. The shell driver wrote it into every workspace and never read
		// it; this one reads it, so the workspaces it creates say it is there.
		for _, kv := range []struct{ k, v string }{
			{"name", *newName}, {"project", "pgfuzz-" + *newName},
			{"flavor", *flavor}, {"ref", *ref}, {"sanitizer", *san},
			{"engine", "libfuzzer"}, {"targets", ""},
		} {
			k, v := kv.k, kv.v
			if err := workspace.Set(dir, k, v); err != nil {
				fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
				return 2
			}
		}
		if *plugins != "" {
			workspace.Set(dir, "plugins", *plugins)
		}
		fmt.Printf("created %s\n  next: pgfuzz build -w %s\n", dir, *newName)
		return 0
	}
	ents, err := os.ReadDir(r.WS)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
		return 2
	}
	fmt.Printf("  %-26s %-16s %-11s %-9s %s\n", "WORKSPACE", "REF", "SANITIZER", "TARGETS", "SHA")
	var n int
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		dir := filepath.Join(r.WS, e.Name())
		c, err := workspace.Load(dir)
		if err != nil {
			continue
		}
		built := "-"
		if ts, err := build.Targets(buildDir(dir, c, r)); err == nil {
			built = fmt.Sprint(len(ts))
		}
		fmt.Printf("  %-26s %-16s %-11s %-9s %s\n",
			c.Name, dash(c.Ref), dash(c.Sanitizer), built, dash(c.Get("sha")))
		n++
	}
	fmt.Printf("\n  %d workspaces under %s\n", n, r.WS)
	return 0
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// cmdBootstrap makes a fresh machine able to run a campaign.
//
// The clones are DERIVED state: workspace.conf and plugins.tsv fully determine
// them, so this is a build directory being populated rather than anything
// being restored. It is also the command that proves the binary is
// self-sufficient -- everything it needs is either inside it or cloneable.
func cmdBootstrap(argv []string) int {
	fs := flag.NewFlagSet("bootstrap", flag.ExitOnError)
	cache := fs.String("cache", "", "where the clones live (default $PGFUZZ_CACHE)")
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	if err := fs.Parse(argv); err != nil {
		return 2
	}
	r := paths.Resolve()
	if *cache != "" {
		r.Cache = *cache
	}

	// Checked up front and named individually: "bootstrap failed" sends
	// somebody reading a log, "git is not installed" does not.
	missing := 0
	for _, bin := range []string{"docker", "git", "python3"} {
		if _, err := exec.LookPath(bin); err != nil {
			fmt.Fprintf(os.Stderr, "  missing: %s\n", bin)
			missing++
		}
	}
	if err := exec.Command("docker", "info").Run(); err != nil {
		fmt.Fprintln(os.Stderr, "  cannot talk to the docker daemon")
		missing++
	}
	if missing > 0 {
		fmt.Fprintf(os.Stderr, "pgfuzz: %d prerequisite(s) missing\n", missing)
		return 2
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	for _, c := range []struct{ dir, url string }{
		{"postgres", "https://github.com/postgres/postgres.git"},
		{"orioledb-postgres", "https://github.com/orioledb/postgres.git"},
		{"orioledb", "https://github.com/orioledb/orioledb.git"},
		{"oss-fuzz", "https://github.com/google/oss-fuzz.git"},
	} {
		dst := filepath.Join(r.Cache, c.dir)
		if fileExists(filepath.Join(dst, ".git")) {
			fmt.Printf("  have %s\n", c.dir)
			continue
		}
		fmt.Printf("  cloning %s into %s\n", c.dir, dst)
		cmd := exec.CommandContext(ctx, "git", "clone", c.url, dst)
		cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "pgfuzz: cloning %s: %v\n", c.dir, err)
			return 1
		}
	}

	// PUT THE SUBSTRATE WHERE THE PIN SAYS.
	//
	// A clone lands on whatever master is today. Leaving it there made the
	// substrate stable only by accident -- bootstrap skips an existing clone,
	// so it froze wherever it first landed, and a second machine froze
	// somewhere else. Checking the pin out makes two machines agree.
	if home, err := r.NeedHome(); err == nil {
		if pin, err := archive.ReadPin(home); err == nil {
			oss := r.OSSFuzz()
			if archive.Commit(oss, false) != pin.Commit {
				fmt.Printf("  checking oss-fuzz out at the pinned %s\n", pin.Commit[:12])
				exec.CommandContext(ctx, "git", "-C", oss, "fetch", "--quiet", "origin").Run()
				co := exec.CommandContext(ctx, "git", "-C", oss, "checkout", "--quiet", pin.Commit)
				co.Stderr = os.Stderr
				if err := co.Run(); err != nil {
					fmt.Fprintf(os.Stderr, "pgfuzz: could not check out the pinned commit: %v\n", err)
					return 1
				}
			}
			for _, m := range pin.Check(oss) {
				// Reported, not fatal: bootstrap's job is to get you close
				// enough to build, and build refuses if it is still wrong.
				fmt.Fprintf(os.Stderr, "  substrate still differs:\n%s\n", m)
			}
		}
	}
	fmt.Printf("\nready. clones under %s\n", r.Cache)
	fmt.Printf("next: pgfuzz build -w <workspace>\n")
	return 0
}

// cmdStop ends running fuzzing containers.
//
// By CONTAINER, not by process. Killing the client leaves the container
// running -- docker's client dying does not stop what it started -- and a
// campaign that "stopped" while eighteen containers kept fuzzing is how a
// rebuild lands on a tree something is still executing out of.
func cmdStop(argv []string) int {
	fs := flag.NewFlagSet("stop", flag.ExitOnError)
	ws := fs.String("w", "", "only this workspace's containers")
	slug := fs.String("slug", "", "also stop this campaign's driver")
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	if err := fs.Parse(argv); err != nil {
		return 2
	}
	// THE DRIVER FIRST, or stopping containers is pointless: a campaign that
	// survives TERM immediately starts the next target's container, so the
	// stop races the thing it is stopping. The old script said exactly this.
	if *slug != "" {
		r := paths.Resolve()
		slugDir := filepath.Join(r.Campaigns(), *slug)
		if pid := campaign.LiveDriver(slugDir); pid > 0 {
			syscall.Kill(pid, syscall.SIGTERM)
			fmt.Printf("asked campaign %s (pid %d) to stop\n", *slug, pid)
			// A moment for it to put its own containers down; it reaps on
			// exit now, so this usually leaves nothing below to do.
			time.Sleep(2 * time.Second)
		}
	}

	filter := "name=pgfuzz-run-"
	if *ws != "" {
		filter = "name=pgfuzz-run-" + *ws + "-"
	}
	out, err := exec.Command("docker", "ps", "-q", "--filter", filter).Output()
	if err != nil {
		fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
		return 2
	}
	ids := strings.Fields(string(out))
	if len(ids) == 0 {
		fmt.Println("nothing running")
		return 0
	}
	killed := 0
	for _, id := range ids {
		if exec.Command("docker", "kill", id).Run() == nil {
			killed++
		}
	}
	fmt.Printf("stopped %d container(s)\n", killed)
	if killed < len(ids) {
		fmt.Printf("  %d would not stop -- check `docker ps`\n", len(ids)-killed)
		return 1
	}
	return 0
}

// cmdStorage generates and runs new scenarios.
//
// The generator is NOT bit-compatible with the Python one and does not need to
// be: a recorded finding carries its whole scenario as JSON rather than a seed
// number, precisely because the generator changed and a seed stopped producing
// what it once produced. This finds new ones; `pgfuzz scenario` replays
// recorded ones.
func cmdStorage(argv []string) int {
	fs := flag.NewFlagSet("storage", flag.ExitOnError)
	ws := fs.String("w", "", "workspace")
	seeds := fs.Int("seeds", 20, "how many scenarios")
	start := fs.Int("start-seed", 0, "first seed")
	out := fs.String("o", "", "write failing scenarios here (default: the workspace's artifacts)")
	timeout := fs.Duration("timeout", 20*time.Minute, "per scenario")
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
	if *out == "" {
		*out = filepath.Join(dir, "artifacts", "storage")
	}
	if err := os.MkdirAll(*out, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
		return 2
	}
	orioledb := c.Get("flavor") == "orioledb"

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var failures int
	for i := 0; i < *seeds; i++ {
		if ctx.Err() != nil {
			break
		}
		seed := *start + i
		sc := scenario.Generate(seed, orioledb)
		// The generated scenario goes to disk first: the container reads a
		// file, and a scenario that is only in memory cannot be re-run.
		tmp := filepath.Join(*out, fmt.Sprintf(".seed%d.json", seed))
		if b, err := json.MarshalIndent(scenario.Record{Seed: seed, Scenario: sc}, "", " "); err == nil {
			os.WriteFile(tmp, b, 0o644)
		}
		res, err := pgserver.Run(ctx, pgserver.Request{
			Image:    "gcr.io/oss-fuzz/" + c.Project,
			Out:      buildDir(dir, c, r),
			Scenario: tmp,
			Timeout:  *timeout,
		})
		os.Remove(tmp)
		verdict := scenario.ResultLine(res.Output)
		switch {
		case verdict == "" || strings.HasPrefix(verdict, "setup-failed:"):
			// Not a finding: the scenario never got built, so it says nothing
			// either way. Counting it as one is the mistake this whole tool
			// exists to prevent.
			fmt.Printf("  seed %-5d could not run: %s\n", seed, firstLine(verdict, err))
		case verdict == "clean":
			fmt.Printf("  seed %-5d clean\n", seed)
		default:
			failures++
			fmt.Printf("  seed %-5d \033[31mFAIL\033[0m %s\n", seed, clip(verdict, 70))
			// The scenario, not the seed: the generator will change, and then
			// this seed builds something else. A recorded number is a label;
			// a recorded scenario is a reproducer.
			// NOTES TRAVEL WITH THE ARTIFACT. A note is a perturbation that
			// did not happen, or one that happened and was expected -- a
			// refusal, a deadlock under contention. Without them a scenario
			// that skipped half its steps is indistinguishable from one that
			// ran them, and a reproducer's worth depends on which it was.
			rec := scenario.Record{
				Seed: seed, Failure: verdict, Scenario: sc,
				Notes: scenario.NoteLines(res.Output),
			}
			if b, err := json.MarshalIndent(rec, "", " "); err == nil {
				os.WriteFile(filepath.Join(*out, fmt.Sprintf("seed%d.json", seed)),
					append(b, '\n'), 0o644)
				os.WriteFile(filepath.Join(*out, fmt.Sprintf("seed%d.sql", seed)),
					[]byte(scenario.RenderSetup(sc)), 0o644)
			}
		}
	}
	fmt.Printf("\n%d scenario(s), %d failure(s) -> %s\n", *seeds, failures, *out)
	if failures > 0 {
		return 1
	}
	return 0
}

func firstLine(v string, err error) string {
	if v != "" {
		return clip(v, 60)
	}
	if err != nil {
		return clip(err.Error(), 60)
	}
	return "no result line"
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// verdicts are the only answers triage accepts.
//
// A closed set on purpose. "looks fine" and "probably ok" are not verdicts,
// and an artifact filed under one is an artifact nobody will ever look at
// again -- which is the same as deleting it, without saying so.
var verdicts = []string{"real-bug", "harness", "duplicate", "noise"}

func cmdTriage(argv []string) int {
	fs := flag.NewFlagSet("triage", flag.ExitOnError)
	ws := fs.String("w", "", "workspace")
	target := fs.String("t", "", "target")
	verdict := fs.String("verdict", "", strings.Join(verdicts, " | "))
	why := fs.String("why", "", "one line of reasoning, recorded with the verdict")
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	if err := fs.Parse(argv); err != nil || *ws == "" || *target == "" || fs.NArg() != 1 {
		fs.Usage()
		return 2
	}
	ok := false
	for _, v := range verdicts {
		if *verdict == v {
			ok = true
		}
	}
	if !ok {
		fmt.Fprintf(os.Stderr, "pgfuzz: verdict must be one of: %s\n", strings.Join(verdicts, ", "))
		return 2
	}
	dir, c, _, err := openWS(*ws)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
		return 2
	}
	src := fs.Arg(0)
	fi, err := os.Stat(src)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pgfuzz: no such artifact: %s\n", src)
		return 2
	}

	// MOVED, not deleted. A triaged artifact stays on disk under triaged/ so a
	// verdict can be revisited -- several here have been, and one reversal
	// turned "harness artifact" back into a confirmed cluster-fatal defect.
	dst := filepath.Join(dir, "artifacts", *target, "triaged")
	if err := os.MkdirAll(dst, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
		return 2
	}
	base := filepath.Base(src)
	out := filepath.Join(dst, base)
	if err := moveFile(src, out); err != nil {
		fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
		return 2
	}

	lines := []string{
		"**Build:** " + dash(c.Ref) + " (" + dash(c.Get("sha")) + "), " + dash(c.Sanitizer),
		fmt.Sprintf("**What:** `%s` (%d bytes)", base, fi.Size()),
		"**Verdict:** " + *verdict,
	}
	if *why != "" {
		lines = append(lines, "**Why:** "+*why)
	}
	lines = append(lines,
		fmt.Sprintf("**Reproduce:** `pgfuzz repro -w %s -t %s artifacts/%s/triaged/%s`",
			c.Name, *target, *target, base),
		"**Next:** re-open if the reasoning above does not hold")
	if err := appendWorklog(dir, fmt.Sprintf("Triage — %s/%s: %s", *target, base, *verdict), lines); err != nil {
		fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
		return 2
	}
	fmt.Printf("%s -> triaged/%s  (%s)\n", base, base, *verdict)
	return 0
}

func cmdLog(argv []string) int {
	fs := flag.NewFlagSet("log", flag.ExitOnError)
	ws := fs.String("w", "", "workspace")
	title := fs.String("title", "", "one-line title")
	var lines wsList
	fs.Var(&lines, "line", "a body line (repeatable)")
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	if err := fs.Parse(argv); err != nil || *ws == "" || *title == "" {
		fs.Usage()
		return 2
	}
	dir, _, _, err := openWS(*ws)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
		return 2
	}
	if err := appendWorklog(dir, *title, lines); err != nil {
		fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
		return 2
	}
	fmt.Printf("logged: %s\n", *title)
	return 0
}

// appendWorklog adds an entry to the workspace's own log.
//
// Append-only and per workspace: the log is the record of what was done to
// THIS tree, and a campaign that rewrites history loses the one account of
// why a build is the way it is.
func appendWorklog(dir, title string, lines []string) error {
	f, err := os.OpenFile(filepath.Join(dir, "WORKLOG.md"),
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	fmt.Fprintf(f, "\n## %s — %s\n\n", time.Now().Format("2006-01-02"), title)
	for _, l := range lines {
		fmt.Fprintln(f, l)
	}
	return nil
}

// moveFile renames, falling back to copy-and-remove across filesystems.
//
// os.Rename cannot cross a device, and artifacts routinely do: /tmp is a
// tmpfs and the workspaces are on disk. The copy happens before the remove,
// so a failure loses nothing -- the wrong order would delete an artifact that
// never arrived.
func moveFile(src, dst string) error {
	if err := os.Rename(src, dst); err == nil {
		return nil
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	out, err := os.Create(dst)
	if err != nil {
		in.Close()
		return err
	}
	_, cerr := io.Copy(out, in)
	in.Close()
	if err := out.Close(); err != nil && cerr == nil {
		cerr = err
	}
	if cerr != nil {
		os.Remove(dst)
		return cerr
	}
	return os.Remove(src)
}

// cmdIndex writes the campaign history page.
//
// One row per archived run, newest first, so "what happened here" is a page
// rather than a directory listing sorted by name -- and campaign directories
// sort by name into an order that has nothing to do with time.
func cmdIndex(argv []string) int {
	fs := flag.NewFlagSet("index", flag.ExitOnError)
	slug := fs.String("slug", "", "campaign (default: every one)")
	out := fs.String("o", "", "write here (default: campaigns/<slug>/index.html)")
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	if err := fs.Parse(argv); err != nil {
		return 2
	}
	r := paths.Resolve()
	slugs := []string{}
	if *slug != "" {
		slugs = append(slugs, *slug)
	} else {
		ents, err := os.ReadDir(r.Campaigns())
		if err != nil {
			fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
			return 2
		}
		for _, e := range ents {
			if e.IsDir() {
				slugs = append(slugs, e.Name())
			}
		}
	}
	if len(slugs) == 0 {
		fmt.Fprintln(os.Stderr, "pgfuzz: no campaigns")
		return 2
	}
	wrote := 0
	for _, sl := range slugs {
		dest := *out
		if dest == "" {
			dest = filepath.Join(r.Campaigns(), sl, "index.html")
		}
		d, err := report.GatherIndex(r.Campaigns(), sl)
		if err != nil {
			fmt.Fprintf(os.Stderr, "pgfuzz: %s: %v\n", sl, err)
			continue
		}
		f, err := os.Create(dest)
		if err != nil {
			fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
			continue
		}
		err = report.RenderIndex(f, d)
		f.Close()
		if err != nil {
			fmt.Fprintf(os.Stderr, "pgfuzz: %s: %v\n", sl, err)
			continue
		}
		fmt.Printf("%s  %d run(s)\n", dest, len(d.Runs))
		wrote++
	}
	if wrote == 0 {
		return 1
	}
	return 0
}

func cmdBundle(argv []string) int {
	fs := flag.NewFlagSet("bundle", flag.ExitOnError)
	slug := fs.String("slug", "", "campaign")
	covWS := fs.String("cov", "", "coverage workspace to measure")
	noCorpus := fs.Bool("no-corpus", false, "omit corpus archives")
	outDir := fs.String("out", "", "where the bundle lands (default: campaigns/<slug>)")
	baseline := fs.String("baseline", "", "ubsan accept-list for the gates")
	force := fs.Bool("force", false, "bundle even while the campaign is still running")
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	if err := fs.Parse(argv); err != nil || *slug == "" {
		fs.Usage()
		return 2
	}
	r := paths.Resolve()
	campDir := filepath.Join(r.Campaigns(), *slug)

	// A REPORT IS NOT BUILT OVER A MOVING TARGET.
	//
	// The old bundle warned and recorded the fact in its manifest; the archive
	// refused outright, because an archive of a campaign still adding to
	// itself is an archive of nothing. Coverage is the sharpest case: measured
	// against a corpus that is growing right now, the number belongs to no
	// run. -force is for the case where somebody knows better.
	if pid := campaign.LiveDriver(campDir); pid > 0 && !*force {
		fmt.Fprintf(os.Stderr,
			"pgfuzz: campaign %s is still running (pid %d) -- bundle a FINISHED one,\n"+
				"  or pass -force to bundle a moving target and have it recorded as such\n",
			*slug, pid)
		return 2
	} else if pid > 0 {
		fmt.Fprintf(os.Stderr,
			"pgfuzz: !! bundling %s while it is still running (pid %d);"+
				" the numbers describe a moving target\n", *slug, pid)
	}
	if *outDir == "" {
		// ONE LEVEL DOWN, not into the run namespace. `pgfuzz index` treats
		// any subdirectory of the slug holding a MANIFEST.json as an archived
		// RUN, and a bundle writes one -- so every bundle became a phantom row
		// on the campaign history, rendering ? and - across the board and
		// flipping a "definition widened" notice on a directory that is not a
		// run.
		*outDir = filepath.Join(campDir, "bundles")
	}
	stage := filepath.Join(*outDir, bundle.Name(*slug, time.Now()))
	if err := os.MkdirAll(stage, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
		return 2
	}
	m := &bundle.Manifest{Slug: *slug, Built: time.Now().UTC(), Tool: "pgfuzz (go)"}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// 1. THE GATES FIRST, and their verdict goes in the manifest. A bundle
	// built over a failing gate is still produced -- you often want the
	// evidence precisely when something is wrong -- but it must say so.
	m.GatesPass = true
	if entries, err := os.ReadFile(filepath.Join(campDir, "live", "entries")); err == nil {
		for _, ws := range strings.Fields(string(entries)) {
			if code := runGateQuiet(r, ws, *baseline); code == 1 {
				m.GatesPass = false
				m.Add("gate:"+ws, false, "a gate failed for this workspace")
			}
		}
	}
	if m.GatesPass {
		m.Add("gates", true, "no gate failed")
	}

	// 2. Coverage, measured now rather than reused, unless there is none.
	var cov *coverage.Summary
	if *covWS != "" {
		dir, c, _, err := openWS(*covWS)
		if err != nil {
			m.Add("coverage", false, err.Error())
		} else {
			profiles, _ := coverage.FindProfiles(r.WS)
			if len(profiles) == 0 {
				m.Add("coverage", false, "no per-target profiles on disk")
			} else if sum, err := coverage.Union(ctx, coverage.UnionRequest{
				Out: buildDir(dir, c, r), Profiles: profiles,
				Stage: filepath.Join(dir, ".union"), Timeout: 90 * time.Minute,
			}); err != nil {
				m.Add("coverage", false, err.Error())
			} else {
				cov = &sum
				m.Add("coverage", true, fmt.Sprintf("%.2f%% lines over %d targets",
					sum.Lines.Pct(), sum.Targets))
			}
		}
	} else {
		m.Add("coverage", false, "not requested (-cov)")
	}

	// 3. Gather THEN render, in that order and never the other way: rendering
	// alone reports whatever the last gather saw.
	series := campaign.Series{Path: filepath.Join(campDir, "series.jsonl")}
	d, err := report.Gather(*slug, series, filepath.Join(r.WS, "FINDINGS"), cov)
	// The same provenance the standalone report carries. Rendering the bundle
	// through a second call site is how the section came to be missing from
	// exactly the copy that gets handed to somebody else.
	if man, merr := campaign.ReadManifest(campDir); merr == nil {
		d.WithManifest(man)
	}
	if err != nil {
		m.Add("gather", false, err.Error())
	} else {
		m.RunID = d.RunID
		m.Add("gather", true, fmt.Sprintf("%d slices, %d findings", d.Slices, len(d.Findings)))
	}
	if f, err := os.Create(filepath.Join(stage, "index.html")); err == nil {
		err = report.Render(f, d)
		f.Close()
		m.Add("render", err == nil, "index.html")
	} else {
		m.Add("render", false, err.Error())
	}

	// 4. The record itself.
	if err := bundle.CopyInto(stage, "series.jsonl", series.Path); err != nil {
		m.Add("series", false, err.Error())
	} else {
		m.Add("series", true, "series.jsonl")
	}

	// THE DOCUMENTS THE GATES AND THE COVERAGE WERE JUDGED AGAINST.
	//
	// The bundle recorded that no gate failed and did not ship the floors
	// those gates compared against, so the claim could not be rechecked by
	// whoever received it -- the one thing a bundle exists for. Same for the
	// coverage series: a single union percentage says nothing about whether
	// coverage was climbing or flat.
	//
	// Each is named in the manifest whether or not it was found. A document
	// that is absent must SAY it is absent; silently shipping nine of ten and
	// listing nine is how a bundle comes to look complete.
	scripts := filepath.Join(r.Home, "scripts")
	for _, doc := range []struct{ name, path, why string }{
		{"ratchet-baseline.json", filepath.Join(scripts, "ratchet-baseline.json"),
			"the floors every gate in this campaign compared against"},
		{"ratchet-series.jsonl", filepath.Join(scripts, "ratchet-series.jsonl"),
			"how those floors moved, run by run"},
		{"coverage-series.jsonl", filepath.Join(scripts, "coverage-series.jsonl"),
			"coverage over time, which one union percentage cannot show"},
		{"coverage-components.jsonl", filepath.Join(scripts, "coverage-components.jsonl"),
			"coverage split by component"},
		{"campaign-stopped.marker", finalreport.MarkerPath(r.WS),
			"when the run stopped, and each corpus size at that moment"},
	} {
		if err := bundle.CopyInto(stage, doc.name, doc.path); err != nil {
			m.Add(doc.name, false, "not shipped: "+err.Error())
		} else {
			m.Add(doc.name, true, doc.why)
		}
	}

	if b := census.New(); true {
		var logs int
		known := map[string]string{}
		if entries, err := os.ReadFile(filepath.Join(campDir, "live", "entries")); err == nil {
			for _, ws := range strings.Fields(string(entries)) {
				logs += addWorkspaceLogs(b, r, ws)
				if _, c, _, err := openWS(ws); err == nil {
					known[ws] = c.Sanitizer
				}
			}
		}
		if logs == 0 {
			m.Add("census", false, "no logs to scan")
		} else if err := b.Write(stage, known); err != nil {
			m.Add("census", false, err.Error())
		} else {
			m.Add("census", true, fmt.Sprintf("%d signatures from %d logs", len(b.Rows()), logs))
		}
	}
	if !*noCorpus {
		var total int64
		archived := 0
		var failed []string
		if entries, err := os.ReadFile(filepath.Join(campDir, "live", "entries")); err == nil {
			for _, ws := range strings.Fields(string(entries)) {
				src := filepath.Join(r.WS, ws, "corpus")
				if !fileExists(src) {
					continue
				}
				// VERIFIED AGAINST A COUNT TAKEN FROM THE SOURCE, not
				// against the archive's own byte total -- an archive short by
				// a few files looks exactly like a complete one.
				note, err := bundle.ArchiveDirCounted(stage,
					filepath.Join("corpus", ws+".tar.gz"), src)
				if err != nil {
					failed = append(failed, ws+": "+err.Error())
					continue
				}
				total += note.Bytes
				archived += note.Archived
			}
		}
		switch {
		case len(failed) > 0:
			m.Add("corpus", false, strings.Join(failed, "; "))
		case total == 0:
			m.Add("corpus", false, "no corpus found for this campaign's workspaces")
		default:
			m.Add("corpus", true, fmt.Sprintf("%s inputs, verified (%s)",
				comma(archived), humanBytes(total)))
		}
	} else {
		m.Add("corpus", true, "omitted by -no-corpus")
	}

	if err := m.Write(stage); err != nil {
		fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
		return 2
	}
	tgz := stage + ".tar.gz"
	size, err := bundle.Archive(stage, tgz)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pgfuzz: archive: %v\n", err)
		return 1
	}

	fmt.Print(m.Summary())
	fmt.Printf("\n%s\n%s  %s\n", stage, tgz, comma(int(size))+" bytes")
	if f := m.Failed(); len(f) > 0 {
		// Named, not counted: "3 stages failed" sends somebody to a log.
		fmt.Printf("\nbundle produced with %d stage(s) failed: %s\n",
			len(f), strings.Join(f, ", "))
		fmt.Println("it is still the evidence -- the manifest records what did not run")
		return 1
	}
	return 0
}

// runGateQuiet judges one workspace without printing.
func runGateQuiet(r paths.Roots, ws, baselinePath string) int {
	dir, c, _, err := openWS(ws)
	if err != nil {
		return 2
	}
	if baselinePath == "" {
		home, err := r.NeedHome()
		if err != nil {
			fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
			return 2
		}
		baselinePath = filepath.Join(home, "scripts", "ubsan-baseline.tsv")
	}
	accepted, _ := gate.LoadAccepted(baselinePath)
	runLogs := gatherRunLogs(dir)
	if len(runLogs) == 0 {
		return 2
	}
	// The same acknowledgement list the ratchet uses. A starvation floor
	// nobody can acknowledge is a floor people learn to ignore.
	starveAcks := map[string]string{}
	if pp, err := profilePaths(r, ""); err == nil {
		starveAcks, _ = ratchet.LoadAcks(pp.Acks)
	}
	for _, lg := range runLogs {
		st, err := logs.ParseFile(lg)
		if err != nil {
			continue
		}
		st.Target = targetOf(lg)
		for _, v := range []gate.Verdict{
			gate.Starvation(st, 10000, starveAcks), gate.SlowUnits(st),
			gate.UBSan(st, c.Name, accepted),
		} {
			if v.Failed {
				return 1
			}
		}
	}
	return 0
}

func addWorkspaceLogs(b *census.Builder, r paths.Roots, ws string) int {
	dir := filepath.Join(r.WS, ws)
	var n int
	for _, pat := range []string{
		"soak-*_fuzzer.log", "soak-*_fuzzer.log.gz",
		"artifacts/*/run-*.log", "artifacts/*/run-*.log.gz",
		"sweep-round*.log", "sweep-round*.log.gz"} {
		hits, _ := filepath.Glob(filepath.Join(dir, pat))
		for _, p := range hits {
			f, err := os.Open(p)
			if err != nil {
				continue
			}
			if strings.HasPrefix(filepath.Base(p), "sweep-round") {
				b.AddReader(ws, f)
			} else {
				b.AddReaderAs(ws, targetOf(p), f)
			}
			f.Close()
			n++
		}
	}
	return n
}

// corpusMinimize shrinks corpora, printing one line per target.
//
// Every target by default: starvation is a per-target state, and a run that
// minimises only what was named leaves the locked-out target locked out.
func corpusMinimize(wsDir, bdir, root string, only []string, o corpus.MinOptions) int {
	targets := only
	if len(targets) == 0 {
		ents, _ := os.ReadDir(root)
		for _, e := range ents {
			if e.IsDir() {
				targets = append(targets, e.Name())
			}
		}
	}
	if len(targets) == 0 {
		fmt.Fprintln(os.Stderr, "pgfuzz: no corpora to minimize")
		return 2
	}
	rc := 0
	for _, t := range targets {
		lf, err := os.Create(filepath.Join(wsDir, "corpus-minimize-"+t+".log"))
		if err != nil {
			fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
			return 2
		}
		o.Log = lf
		res, err := corpus.Minimize(wsDir, bdir, t, o)
		lf.Close()
		switch {
		case err != nil:
			// Not fatal for the other targets: one merge that fails must not
			// leave the rest of the workspace unminimised.
			fmt.Printf("  %-28s ERROR %v\n", t, err)
			rc = 1
		case res.Skipped != "":
			fmt.Printf("  %-28s skipped -- %s\n", t, res.Skipped)
		case res.Reason != "":
			fmt.Printf("  %-28s %s\n", t, res.Reason)
		default:
			pct := 100.0 * float64(res.After) / float64(res.Before)
			fmt.Printf("  %-28s %s -> %s inputs (%.1f%% kept)\n",
				t, comma(res.Before), comma(res.After), pct)
			if res.Archived > 0 {
				fmt.Printf("  %-28s   archived %s capped input(s)\n", "", comma(res.Archived))
			}
			if res.Backup != "" {
				fmt.Printf("  %-28s   previous corpus kept at %s\n", "", res.Backup)
			}
		}
	}
	return rc
}

func cmdWatchdog(argv []string) int {
	fs := flag.NewFlagSet("watchdog", flag.ExitOnError)
	grace := fs.Int("grace", 300, "seconds past -max_total_time before acting")
	interval := fs.Int("interval", 60, "seconds between sweeps")
	termWait := fs.Int("term-wait", 20, "seconds SIGTERM gets to flush final stats")
	logPath := fs.String("log", "", "append to this file as well as stdout")
	once := fs.Bool("n", false, "one sweep, then exit")
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	if err := fs.Parse(argv); err != nil {
		return 2
	}

	var w io.Writer = os.Stdout
	if *logPath != "" {
		f, err := os.OpenFile(*logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
			return 2
		}
		defer f.Close()
		// Both, not either: a watchdog started in the foreground still has to
		// leave the durable record the log is read as evidence from.
		w = io.MultiWriter(os.Stdout, f)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	err := watchdog.Run(ctx, watchdog.Options{
		Grace:    time.Duration(*grace) * time.Second,
		Interval: time.Duration(*interval) * time.Second,
		TermWait: time.Duration(*termWait) * time.Second,
		Log:      w,
		Once:     *once,
	})
	if err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
		return 1
	}
	return 0
}

func cmdTidy(argv []string) int {
	fs := flag.NewFlagSet("tidy", flag.ExitOnError)
	apply := fs.Bool("apply", false, "actually compress; without it this only reports")
	minMB := fs.Int("min-mb", 10, "ignore logs smaller than this")
	minAge := fs.Duration("min-age", time.Hour, "ignore logs written more recently than this")
	withDocker := fs.Bool("docker", false, "also prune stopped containers and dangling layers")
	root := fs.String("root", paths.Resolve().WS, "where to look")
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	if err := fs.Parse(argv); err != nil {
		return 2
	}

	cands, err := tidy.Scan(tidy.Options{
		Root: *root, MinBytes: int64(*minMB) << 20, MinAge: *minAge,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
	}
	if len(cands) == 0 {
		fmt.Println("  no logs over the threshold; nothing to compress")
	}
	var total, saved int64
	for _, c := range cands {
		total += c.Bytes
		if !*apply {
			fmt.Printf("  %10s  %s\n", corpus.Human(c.Bytes), c.Path)
			continue
		}
		s, err := tidy.Compress(c)
		if err != nil {
			fmt.Printf("  %10s  %s -- FAILED: %v\n", corpus.Human(c.Bytes), c.Path, err)
			continue
		}
		saved += s
		fmt.Printf("  %10s -> %-10s %s.gz\n", corpus.Human(c.Bytes),
			corpus.Human(c.Bytes-s), c.Path)
	}
	if len(cands) > 0 {
		if *apply {
			fmt.Printf("\n  compressed %d log(s), reclaimed %s. Nothing was deleted.\n",
				len(cands), corpus.Human(saved))
		} else {
			fmt.Printf("\n  %d log(s), %s. Re-run with -apply to compress them.\n",
				len(cands), corpus.Human(total))
		}
	}

	if *withDocker {
		stopped, dangling, kept, err := tidy.DockerReclaim(context.Background(), *apply)
		if err != nil {
			fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
		}
		verb := "would remove"
		if *apply {
			verb = "removed"
		}
		fmt.Printf("\n  docker: %s %d stopped container(s) and %d dangling layer(s)\n",
			verb, stopped, dangling)
		// Not a footnote: this is the line that says why the reclaim looks
		// small next to `docker system df`.
		fmt.Printf("  docker: kept %d locally built pgfuzz-* image(s) -- hours to rebuild\n", kept)
	}
	return 0
}

func cmdPlugins(argv []string) int {
	fs := flag.NewFlagSet("plugins", flag.ExitOnError)
	path := fs.String("f", "plugins.tsv", "the registry to verify")
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	if err := fs.Parse(argv); err != nil {
		return 2
	}
	ps, err := build.ReadPlugins(*path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
		return 2
	}
	out, fail := build.FormatPluginChecks(
		build.VerifyPlugins(context.Background(), ps, fs.Args()))
	fmt.Print(out)
	if fail > 0 {
		return 1
	}
	return 0
}

func cmdRedGreen(argv []string) int {
	fs := flag.NewFlagSet("redgreen", flag.ExitOnError)
	root := fs.String("root", ".", "the pg-fuzz checkout holding tests/ossfuzz/")
	clone := fs.String("clone", filepath.Join(os.Getenv("HOME"), "Projects/fuzzing/oss-fuzz-pr"),
		"a fresh google/oss-fuzz clone; this one is BUILT AND MODIFIED")
	green := fs.Bool("green", false, "apply every fix; without it only each group's prerequisites")
	only := fs.String("case", "", "run one case by id")
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	if err := fs.Parse(argv); err != nil {
		return 2
	}
	res, err := redgreen.Run(context.Background(), redgreen.Options{
		Root: *root, Clone: *clone, Green: *green, Only: *only, Out: os.Stdout,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
		return 2
	}
	// A case that came out the other way is the only failure: skipped cases
	// are reported and counted, not swallowed.
	if res.Unexpected > 0 {
		return 1
	}
	return 0
}

// ratchetModes selects which of the read-only analyses to run.
type ratchetModes struct {
	Show, Cusum, Activity, Distribution, Variance bool
	Since                                         string
	Top                                           int
}

// ratchetAnalysis runs the analyses that read the accumulated record rather
// than one round.
//
// Every path here is READ-ONLY. Nothing raises a floor, and nothing writes the
// baseline: an analysis that can change what it is analysing gives an answer
// that cannot be checked twice.
func ratchetAnalysis(ws, basePath, profile string, m ratchetModes) int {
	r := paths.Resolve()
	pp, err := profilePaths(r, profile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
		return 2
	}
	if basePath == "" {
		basePath = pp.Baseline
	}
	b, err := pp.LoadBaseline(basePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
		return 2
	}
	seriesPath, historyPath := pp.Series, pp.History

	rc := 0
	if m.Show {
		ratchet.Show(os.Stdout, b, ws)
	}
	if m.Cusum {
		var only []string
		if ws != "" {
			only = []string{ws}
		}
		if n := ratchet.Cusum(os.Stdout, ratchet.ReadJSONL[ratchet.SeriesRow](seriesPath),
			only, ratchet.DefaultCusum()); n > rc {
			rc = n
		}
	}
	if m.Activity {
		ratchet.Activity(os.Stdout, ratchet.ReadJSONL[ratchet.HistoryRow](historyPath),
			m.Since, m.Top)
	}
	if m.Distribution {
		acks, err := ratchet.LoadAcks(pp.Acks)
		if err != nil {
			// Reported, not fatal: an unreadable acknowledgement list means
			// every acknowledged row is about to be counted as a failure, and
			// that inflation must be visible rather than inferred.
			fmt.Fprintf(os.Stderr, "pgfuzz: acknowledgements unreadable (%v) -- every\n"+
				"  acknowledged target below will be counted as unacknowledged\n", err)
		}
		ratchet.Distribution(os.Stdout, b, ratchet.ReadJSONL[ratchet.SeriesRow](seriesPath),
			acks, m.Since)
	}
	if m.Variance {
		if n := ratchet.Variance(os.Stdout, ratchet.ReadJSONL[ratchet.SeriesRow](seriesPath), ws); n > rc {
			rc = n
		}
	}
	return rc
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// recordRound appends this round to the series and, if anything moved, to the
// history.
//
// THE SERIES IS WRITTEN EVERY ROUND, whether or not a floor moved. A target
// decaying steadily never beats its record, so it writes nothing to a
// transition log and looks exactly like a target nobody is running -- and the
// drift detector then has no data for precisely the case it exists to catch.
func recordRound(r paths.Roots, pp ProfilePaths, wsDir, ws string, round int, log string,
	obs []ratchet.Observation, res ratchet.UpdateResult) {

	execs := map[string]int{}
	newUnits := map[string]int{}
	for _, o := range obs {
		execs[o.Target] = o.Execs
		// EVERY target, INCLUDING the zeros. "executed and added nothing" is
		// the whole signal here -- spi_query_fuzzer reported a few hundred
		// executions every round for months while adding zero new inputs --
		// and omitting the key makes that indistinguishable from a target that
		// was never measured.
		newUnits[o.Target] = o.NewUnits
	}
	var roundP *int
	if round >= 0 {
		roundP = &round
	}
	var logName *string
	if log != "" {
		n := filepath.Base(log)
		logName = &n
	}
	var runID *string
	if v := os.Getenv("PGFUZZ_RUN_ID"); v != "" {
		runID = &v
	}
	tool := ratchet.ToolCommit(r.Home)
	mtime := ratchet.LogMTime(log)

	rec := ratchet.SeriesRecord{
		WS: ws, Round: roundP, Log: logName, LogMTime: mtime, ToolCommit: tool,
		Execs: execs, NewUnits: newUnits, Corpus: ratchet.CorpusSizes(wsDir),
		RunID: runID, CPUSecs: ratchet.CPUSecs(log),
	}
	if log != "" {
		if reg, err := logs.ParseRegime(log); err == nil {
			rec.Secs, rec.Jobs = &reg.Secs, &reg.Jobs
		}
		if cov, ft, ok := logs.Frontier(log); ok {
			rec.Cov, rec.Ft = &cov, &ft
		}
	}
	if err := ratchet.AppendJSONL(pp.Series, rec); err != nil {
		// Reported, never swallowed: a series that silently stops being
		// written leaves the drift detector reading an ever-staler record
		// while still printing a verdict.
		fmt.Fprintf(os.Stderr, "pgfuzz: could not record the series: %v\n", err)
	}

	if len(res.Changes) == 0 {
		return
	}
	if err := ratchet.AppendJSONL(pp.History, ratchet.HistoryRecord{
		WS: ws, Round: roundP, Log: logName, LogMTime: mtime, ToolCommit: tool,
		Build: ratchet.BuildProvenance(wsDir), Changes: res.Changes,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "pgfuzz: could not record the history: %v\n", err)
	}
}

// cmdReseed lowers a target's floors on purpose, from the rounds still on disk.
func cmdReseed(target, since, reason, basePath, profile string) int {
	r := paths.Resolve()
	pp, err := profilePaths(r, profile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
		return 2
	}
	if basePath == "" {
		basePath = pp.Baseline
	}
	if reason == "" {
		fmt.Fprintln(os.Stderr, "pgfuzz: -reseed needs -reason; a lowered floor with no\n"+
			"  reason is a number somebody later has to take on trust")
		return 2
	}

	// The highest execution count this target reached in any round of a
	// workspace at or after `since`.
	best := func(wsDir, target, since string) int {
		var cut time.Time
		if since != "" {
			for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05", "2006-01-02"} {
				if t, err := time.Parse(layout, since); err == nil {
					cut = t
					break
				}
			}
		}
		out := 0
		for _, n := range ratchet.AllRounds(wsDir) {
			lg := ratchet.SweepLog(wsDir, n)
			if lg == "" {
				continue
			}
			if !cut.IsZero() {
				fi, err := os.Stat(lg)
				if err != nil || fi.ModTime().Before(cut) {
					continue
				}
			}
			per, err := logs.ParseSweep(lg)
			if err != nil {
				continue
			}
			if v := per[target].Execs; v > out {
				out = v
			}
		}
		return out
	}

	var changed []ratchet.ReseedChange
	err = ratchet.WithLock(basePath, func() error {
		b, err := pp.LoadBaseline(basePath)
		if err != nil {
			return err
		}
		dirs := map[string]string{}
		for ws := range b.Floors {
			dirs[ws] = r.Workspace(ws)
		}
		changed, err = b.Reseed(target, since, reason, dirs, best, os.Stdout)
		if err != nil || len(changed) == 0 {
			return err
		}
		return b.Save(basePath)
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
		return 2
	}
	if len(changed) == 0 {
		return 0
	}
	// The history gets the reseed too. A floor that moved without a
	// corresponding history line is a floor whose provenance stops here.
	var cs []ratchet.Change
	for _, c := range changed {
		from := c.From
		cs = append(cs, ratchet.Change{Target: target, Kind: "reseed", From: &from, To: c.To})
	}
	if err := ratchet.AppendJSONL(pp.History, ratchet.HistoryRecord{
		WS: target, ToolCommit: ratchet.ToolCommit(r.Home),
		Build: map[string]string{"reason": reason}, Changes: cs,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "pgfuzz: could not record the history: %v\n", err)
	}
	return 0
}

// productivity reads each workspace's newest new_units figures, so a round cut
// short by the deadline runs its most productive targets first.
func productivity(r paths.Roots, entries []campaign.Entry) map[string]map[string]int {
	path := env("RATCHET_SERIES", filepath.Join(r.Home, "scripts", "ratchet-series.jsonl"))
	rows := ratchet.ReadJSONL[campaign.SeriesNewUnits](path)
	if len(rows) == 0 {
		return nil
	}
	out := map[string]map[string]int{}
	for _, e := range entries {
		if m := campaign.LatestNewUnits(rows, e.Name); len(m) > 0 {
			out[e.Name] = m
		}
	}
	return out
}

func cmdInventory(argv []string) int {
	fs := flag.NewFlagSet("inventory", flag.ExitOnError)
	var wss wsList
	fs.Var(&wss, "w", "workspace (repeatable)")
	asJSON := fs.Bool("json", false, "machine-readable")
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	if err := fs.Parse(argv); err != nil {
		return 2
	}
	r := paths.Resolve()
	if len(wss) == 0 {
		// Every workspace with a build directory. Naming a default pair here
		// would make the inventory of any OTHER campaign silently the
		// inventory of that one -- and an inventory is only meaningful for the
		// run it describes.
		ents, _ := os.ReadDir(r.WS)
		for _, e := range ents {
			if !e.IsDir() {
				continue
			}
			if _, err := os.Stat(filepath.Join(r.WS, e.Name(), "workspace.conf")); err == nil {
				wss = append(wss, e.Name())
			}
		}
	}
	rep := inventory.Collect(inventory.Roots{
		Repo: r.Home, OSSFuzz: r.OSSFuzz(), WSRoot: r.WS, Targets: wss,
	})
	rep.Workspaces = wss
	if *asJSON {
		b, err := json.MarshalIndent(rep, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
			return 2
		}
		fmt.Println(string(b))
	} else {
		layer := ""
		for _, c := range rep.Components {
			if c.Layer != layer {
				layer = c.Layer
				fmt.Printf("\n%s\n", layer)
			}
			mark := " "
			if !c.InFingerprint {
				mark = "-" // recorded, but not part of what defines the run
			}
			fmt.Printf("  %s %-42s %-12s %-18s %s\n", mark, c.Name, c.Kind, c.Hash, c.Detail)
		}
		fmt.Printf("\n  %d component(s); '-' marks those recorded but not in the fingerprint\n",
			len(rep.Components))
	}
	if rep.Unreadable > 0 {
		// Counted and non-zero exit. A component list with a quiet hole in it
		// is worse than one that admits the hole, because the first looks
		// complete.
		fmt.Fprintf(os.Stderr, "  %d component(s) UNREADABLE -- recorded, not skipped\n", rep.Unreadable)
		return 1
	}
	return 0
}

// cmdFinalReport gathers and renders the campaign snapshot.
//
// GATHER THEN RENDER, in that order and through a file. The renderer reads the
// JSON the gather writes, so the data file is the contract between them -- and
// it is shipped in the bundle, which means an archived report can be
// re-rendered years later without the tree that produced it.
func cmdFinalReport(prefix, htmlOut, dataOut, mdOut, from string) int {
	r := paths.Resolve()
	home, err := r.NeedHome()
	if err != nil {
		fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
		return 2
	}
	if htmlOut == "" {
		htmlOut = filepath.Join(r.WS, "FINDINGS", "reports", "campaign-final-report.html")
	}
	if dataOut == "" {
		dataOut = filepath.Join(r.WS, "final-report-data.json")
	}

	// The inventory is gathered here rather than inside the report package:
	// it is the same list `pgfuzz inventory` prints, and two implementations
	// of "what goes into a run" drift the moment a plugin is added.
	var wss []string
	if ents, err := os.ReadDir(r.WS); err == nil {
		for _, e := range ents {
			n := e.Name()
			if e.IsDir() && strings.HasPrefix(n, prefix+"-") && !strings.HasSuffix(n, "-cov") {
				wss = append(wss, n)
			}
		}
	}
	invRep := inventory.Collect(inventory.Roots{
		Repo: home, OSSFuzz: r.OSSFuzz(), WSRoot: r.WS, Targets: wss,
	})
	invRep.Workspaces = wss
	invRaw, err := json.Marshal(invRep)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
		return 2
	}

	// RE-RENDER AN ARCHIVED RUN, which is what the data file is a contract
	// for. A past run's numbers must come from the data.json it shipped: the
	// findings corpus keeps moving, so re-gathering would restate what that
	// run found -- one archived on 2026-08-28 counted eight storage-engine
	// findings where the same directory gives seven today.
	var d finalreport.Data
	if from != "" {
		b, err := os.ReadFile(from)
		if err != nil {
			fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
			return 2
		}
		if err := json.Unmarshal(b, &d); err != nil {
			fmt.Fprintf(os.Stderr, "pgfuzz: %s: %v\n", from, err)
			return 2
		}
		fmt.Printf("  from  %s (archived %s)\n", from, dash(d.Generated))
	} else {
		var err error
		d, err = finalreport.Gather(finalreport.Inputs{
			Repo: home, WSRoot: r.WS, OSSFuzz: r.OSSFuzz(),
			Prefix: prefix, Now: time.Now(),
		}, invRaw)
		if err != nil {
			fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
			return 2
		}
	}
	raw, err := json.MarshalIndent(d, "", " ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
		return 2
	}
	if err := os.MkdirAll(filepath.Dir(dataOut), 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
		return 2
	}
	if err := os.WriteFile(dataOut, append(raw, '\n'), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
		return 2
	}

	var base struct {
		Tolerance  float64                       `json:"tolerance"`
		Floors     map[string]map[string]int     `json:"floors"`
		RateFloors map[string]map[string]float64 `json:"rate_floors"`
	}
	if b, err := os.ReadFile(filepath.Join(home, "scripts", "ratchet-baseline.json")); err == nil {
		json.Unmarshal(b, &base)
	}

	if err := os.MkdirAll(filepath.Dir(htmlOut), 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
		return 2
	}
	f, err := os.Create(htmlOut)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
		return 2
	}
	defer f.Close()
	// ONE INPUTS for however many documents are asked for, so the Markdown
	// and the page cannot describe the run differently.
	// AN ARCHIVED RENDER MUST NOT BORROW TODAY'S FACTS.
	//
	// The union and the stop marker are read from live host state. Rendering
	// an archived run through them dated a run from August with the stop time
	// of a campaign that finished this morning, and showed it either no
	// coverage or somebody else's. Both come from the run's own directory
	// instead -- an archive holds its own series/ beside the report/ it was
	// rendered into -- and are simply absent when it does not have them,
	// which is honest where a borrowed number is not.
	unionPath := filepath.Join(home, "scripts", "coverage-union.jsonl")
	stoppedAt := finalreport.ReadStoppedAt(finalreport.MarkerPath(r.WS))
	if from != "" {
		runDir := filepath.Dir(filepath.Dir(from))
		unionPath = filepath.Join(runDir, "series", "coverage-union.jsonl")
		stoppedAt = finalreport.ReadStoppedAt(
			filepath.Join(runDir, "campaign-stopped.marker"))
	}
	ri := finalreport.RenderInputs{
		Data:   d,
		Union:  finalreport.ReadUnion(unionPath),
		Floors: base.Floors, RateFloors: base.RateFloors, Tolerance: base.Tolerance,
		StoppedAt: stoppedAt,
	}
	err = finalreport.Render(f, ri, report.BaseCSS())
	if err != nil {
		fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
		return 2
	}
	if mdOut != "" {
		mf, err := os.Create(mdOut)
		if err != nil {
			fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
			return 2
		}
		defer mf.Close()
		if err := finalreport.RenderMarkdown(mf, ri); err != nil {
			fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
			return 2
		}
		mst, _ := os.Stat(mdOut)
		fmt.Printf("  wrote %s (%d bytes)\n", mdOut, mst.Size())
	}
	st, _ := os.Stat(htmlOut)
	fmt.Printf("  wrote %s (%d bytes)\n", htmlOut, st.Size())
	fmt.Printf("  data  %s\n", dataOut)
	if invRep.Unreadable > 0 {
		fmt.Printf("  %d component(s) UNREADABLE -- recorded, not skipped\n", invRep.Unreadable)
	}
	return 0
}

// cmdExecReport writes the one-page summary.
func cmdExecReport(prefix, htmlOut string) int {
	r := paths.Resolve()
	home, err := r.NeedHome()
	if err != nil {
		fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
		return 2
	}
	if htmlOut == "" {
		htmlOut = filepath.Join(r.WS, "FINDINGS", "reports", "exec-summary.html")
	}
	if err := os.MkdirAll(filepath.Dir(htmlOut), 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
		return 2
	}
	f, err := os.Create(htmlOut)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
		return 2
	}
	defer f.Close()
	if err := finalreport.RenderExec(f, finalreport.ExecInputs{
		Repo: home, WSRoot: r.WS, Prefix: prefix, Now: time.Now(),
	}, report.BaseCSS()); err != nil {
		fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
		return 2
	}
	st, _ := os.Stat(htmlOut)
	fmt.Printf("  wrote %s (%d bytes)\n", htmlOut, st.Size())
	return 0
}

func setOf(xs []string) map[string]bool {
	if len(xs) == 0 {
		return nil
	}
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		m[x] = true
	}
	return m
}

// corpusAutocap bounds each corpus so seed replay cannot eat the whole slice.
func corpusAutocap(wsDir, ws, bdir, root, logPath string,
	o corpus.AutocapOptions, tuneBudget, apply bool) int {

	if corpus.IsCoverageWorkspace(wsDir) {
		fmt.Printf("  %s is a coverage workspace -- not capping.\n", ws)
		fmt.Println("  replay cost bounds FUZZING; coverage replays a bounded set once.")
		return 0
	}
	if logPath == "" {
		logPath = ratchet.SweepLog(wsDir, -1)
	}
	if logPath == "" {
		fmt.Fprintf(os.Stderr, "pgfuzz: no sweep log for %s\n", ws)
		return 2
	}
	per, err := corpus.ParseSweepForCap(logPath)
	if err != nil || len(per) == 0 {
		fmt.Fprintf(os.Stderr, "pgfuzz: no per-target data in %s\n", filepath.Base(logPath))
		return 2
	}

	fmt.Printf("  %s  <- %s\n", ws, filepath.Base(logPath))
	fmt.Printf("  %-22s %7s %7s %7s %7s %7s  state\n",
		"target", "files", "rate/s", "replay", "budget", "cap")
	var todo []corpus.CapDecision
	for _, d := range corpus.Autocap(wsDir, per, o) {
		fmt.Printf("  %-22s %7d %7d %6.0fs %6ds %7d  %s\n",
			d.Target, d.Files, d.Rate, d.ReplaySeconds, d.Budget, d.Cap, d.State())
		if d.Act {
			todo = append(todo, d)
		}
	}

	r := paths.Resolve()
	if tuneBudget {
		home, err := r.NeedHome()
		if err != nil {
			fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
			return 2
		}
		bpath := filepath.Join(home, "scripts", "target-budgets.tsv")
		cur := corpus.ReadBudgets(bpath)
		for _, ch := range corpus.Tune(ws, per, cur, corpus.DefaultTune()) {
			arrow := "down"
			if ch.Want > ch.Was {
				arrow = "up"
			}
			fmt.Printf("  budget %-4s %-22s %ds -> %ds  (%d new units)\n",
				arrow, ch.Target, ch.Was, ch.Want, ch.Found)
		}
		if apply {
			if err := cur.Write(bpath); err != nil {
				fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
			}
		}
	}

	if len(todo) == 0 {
		fmt.Println("  nothing to cap")
		return 0
	}
	if !apply {
		fmt.Printf("  %d target(s) would be capped; pass -apply to do it\n", len(todo))
		return 0
	}
	home, _ := r.NeedHome()
	removed := filepath.Join(home, "scripts", "autocap-removed.jsonl")
	for _, d := range todo {
		lf, err := os.Create(filepath.Join(wsDir, "corpus-minimize-"+d.Target+".log"))
		if err != nil {
			fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
			continue
		}
		res, err := corpus.Minimize(wsDir, bdir, d.Target, corpus.MinOptions{
			Cap: d.Cap, CapOnly: true, Log: lf,
		})
		lf.Close()
		if err != nil {
			fmt.Printf("  %-22s ERROR %v\n", d.Target, err)
			continue
		}
		// A SKIPPED MINIMISE IS NOT A REMOVAL. Minimize returns early with
		// After == 0 when there is no corpus dir, no binary in the build, or
		// an empty corpus -- so `d.Live - res.After` reported the ENTIRE live
		// corpus as archived. That row is then read back by plateau.Credited
		// and added to corpus growth, so one skipped target permanently
		// inflated the plateau baseline.
		if res.Skipped != "" {
			fmt.Printf("  %-22s skipped: %s\n", d.Target, res.Skipped)
			continue
		}
		n := d.Live - res.After
		if n <= 0 {
			continue
		}
		// Every removal is RECORDED, because a cap is maintenance and must not
		// read as the corpus shrinking on its own.
		if err := corpus.RecordRemoval(removed, corpus.RemovalRecord{
			WS: ws, Target: d.Target, Removed: n,
		}); err != nil {
			fmt.Fprintf(os.Stderr, "pgfuzz: could not record the removal: %v\n", err)
		}
		fmt.Printf("  %-22s capped, %s input(s) archived\n", d.Target, comma(n))
	}
	return 0
}

// cmdFunnel shows how inputs became findings, for one run or two.
func cmdFunnel(path, against string) int {
	recs, err := report.ReadFunnelRecords(path)
	if err != nil || len(recs) == 0 {
		fmt.Fprintf(os.Stderr, "pgfuzz: no records in %s\n", path)
		return 2
	}
	if against == "" {
		report.ShowFunnel(os.Stdout, report.LatestPerTarget(recs),
			filepath.Base(path), report.Rounds(recs))
		return 0
	}
	other, err := report.ReadFunnelRecords(against)
	if err != nil || len(other) == 0 {
		fmt.Fprintf(os.Stderr, "pgfuzz: no records in %s\n", against)
		return 2
	}
	report.CompareFunnels(os.Stdout,
		report.LatestPerTarget(recs), report.LatestPerTarget(other),
		filepath.Base(path), filepath.Base(against))
	return 0
}

// cmdPlateau watches for convergence on a time axis.
func cmdPlateau(argv []string) int {
	fs := flag.NewFlagSet("plateau", flag.ExitOnError)
	var wss wsList
	fs.Var(&wss, "w", "workspace (repeatable)")
	window := fs.Float64("window", 45, "sliding window in minutes")
	interval := fs.Float64("interval", 60, "sampling interval in seconds")
	corpusMargin := fs.Float64("corpus-margin", 1.0, "flat if |growth| is under this %")
	covMargin := fs.Float64("cov-margin", 0.5, "flat if |growth| is under this %")
	consecutive := fs.Int("consecutive", 2, "windows in a row inside margin before PLATEAU")
	patterns := fs.String("log-patterns", "sweep-round,soak-", "live-log prefixes to read cov from")
	once := fs.Bool("n", false, "take one sample, print it, exit")
	maxHours := fs.Float64("max-hours", 0, "give up after this long (0 = no limit)")
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	if err := fs.Parse(argv); err != nil || len(wss) == 0 {
		fs.Usage()
		return 2
	}
	r := paths.Resolve()
	home, err := r.NeedHome()
	if err != nil {
		fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
		return 2
	}
	o := plateau.Defaults()
	o.Window = time.Duration(*window * float64(time.Minute))
	o.Interval = time.Duration(*interval * float64(time.Second))
	o.CorpusMargin, o.CovMargin, o.Consecutive = *corpusMargin, *covMargin, *consecutive
	o.LogPatterns = strings.Split(*patterns, ",")
	o.Once, o.MaxHours = *once, *maxHours
	o.Samples = filepath.Join(home, "scripts", "window-samples.jsonl")
	o.Ledger = filepath.Join(home, "scripts", "autocap-removed.jsonl")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return plateau.Watch(ctx, r.WS, wss, o)
}

// cmdTriageReport generates the reporting triage document from the record.
func cmdTriageReport(argv []string) int {
	fs := flag.NewFlagSet("triage-report", flag.ExitOnError)
	out := fs.String("o", "", "where to write it (default FINDINGS/TRIAGE.md; - for stdout)")
	check := fs.Bool("check", false, "exit 1 if the file on disk is stale")
	family := fs.String("family", "pg17", "version family to lift for")
	note := fs.String("note", "", "provenance line above the document; use when writing\n"+
		"    	into an archive whose other contents are older than this run")
	var wsPat wsList
	fs.Var(&wsPat, "ws", "only findings naming a workspace matching this glob\n"+
		"    	(repeatable, e.g. -ws 'pg17-10-ext-*')")
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	if err := fs.Parse(argv); err != nil {
		return 2
	}
	r := paths.Resolve()
	home, err := r.NeedHome()
	if err != nil {
		fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
		return 2
	}
	findingsRoot := filepath.Join(r.WS, "FINDINGS")
	if *out == "" {
		*out = filepath.Join(findingsRoot, "TRIAGE.md")
	}
	baseline := filepath.Join(home, "scripts", "ubsan-baseline.tsv")

	var findings []triage.Finding
	scoped := map[string][]string{}
	var dropped int
	for _, n := range triage.FindingDirs(findingsRoot) {
		// SCOPE BY WORKSPACE, when asked. Every report over this directory
		// prints all of it under whatever heading it was given, so a campaign
		// that built no storage engine still listed eight storage-engine
		// findings from other campaigns entirely.
		if len(wsPat) > 0 {
			hit, ok := triage.InScope(triage.ReadWriteup(findingsRoot, n, true), wsPat)
			if !ok {
				dropped++
				continue
			}
			scoped[n] = hit
		}
		findings = append(findings, triage.ParseFinding(findingsRoot, n))
	}
	triage.Sort(findings)
	accFiles, accRows := triage.AcceptedUBSan(baseline)
	text := triage.Render(findings,
		triage.LiftCandidates(findingsRoot, r.Campaigns(), baseline, *family),
		triage.Censuses(findingsRoot, r.Campaigns()), accFiles, accRows)
	if len(wsPat) > 0 {
		// SAID AT THE TOP, because the number in this document is the thing
		// people quote. A scoped triage is a different claim from the whole
		// corpus, and attribution here is by MENTION -- no write-up field
		// records the campaign that produced it -- so the document has to
		// carry both facts rather than look like a filtered record.
		var b strings.Builder
		fmt.Fprintf(&b, "> **Scoped to %s.** %d of %d write-ups name a matching\n",
			strings.Join(wsPat, ", "), len(findings), len(findings)+dropped)
		b.WriteString("> workspace; the rest belong to other campaigns and are not listed.\n>\n")
		b.WriteString("> Attribution is by workspace names mentioned in the prose. No field in a\n")
		b.WriteString("> write-up records which campaign produced it, so this is inference, not\n")
		b.WriteString("> provenance: a finding whose author did not name a workspace cannot be\n")
		b.WriteString("> placed and is absent here.\n>\n")
		names := make([]string, 0, len(scoped))
		for n := range scoped {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			fmt.Fprintf(&b, "> - `%s` — %s\n", n, strings.Join(scoped[n], ", "))
		}
		text = b.String() + "\n" + text
	}
	if *note != "" {
		text = "> " + *note + "\n\n" + text
	}

	if *check {
		// Stale is a FAILURE, not a warning. A triage document that has
		// drifted from the record reads exactly like one that has not.
		cur, _ := os.ReadFile(*out)
		if string(cur) != text {
			fmt.Fprintf(os.Stderr, "stale: %s\n", *out)
			return 1
		}
		return 0
	}
	if *out == "-" {
		fmt.Print(text)
		return 0
	}
	if err := os.MkdirAll(filepath.Dir(*out), 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
		return 2
	}
	if err := os.WriteFile(*out, []byte(text), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
		return 2
	}
	fmt.Printf("  wrote %s (%d findings)\n", *out, len(findings))
	return 0
}

// cmdCampaignRecord renders one record file, or compares two.
func cmdCampaignRecord(path, against string) int {
	recs, err := report.ReadCampaignRecords(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
		return 2
	}
	if against == "" {
		return report.CampaignReport(os.Stdout, path, recs)
	}
	other, err := report.ReadCampaignRecords(against)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
		return 2
	}
	return report.CompareCampaigns(os.Stdout, path, against, recs, other)
}

func mtime(p string) time.Time {
	fi, err := os.Stat(p)
	if err != nil {
		return time.Time{}
	}
	return fi.ModTime()
}

func newest(paths []string) time.Time {
	var t time.Time
	for _, p := range paths {
		if m := mtime(p); m.After(t) {
			t = m
		}
	}
	return t
}

// newestPerTarget keeps one log per target: the most recent.
//
// artifacts/<target>/ holds every run that target has ever had. Reading all of
// them and summing would report a slice as having executed everything the
// target did since the workspace was created.
// gatherRunLogs finds a workspace's per-target logs in either layout.
// gatherRunLogs finds the per-target run logs, COMPRESSED OR NOT.
//
// `pgfuzz tidy` gzips these, so a glob for *.log alone means tidying a
// workspace silently empties every gate that reads them -- and an empty gate
// exits 0.
func gatherRunLogs(dir string) []string {
	var out []string
	for _, pat := range []string{"run-*.log", "run-*.log.gz"} {
		m, _ := filepath.Glob(filepath.Join(dir, "artifacts", "*", pat))
		out = append(out, m...)
	}
	if len(out) == 0 {
		for _, pat := range []string{"soak-*_fuzzer.log", "soak-*_fuzzer.log.gz"} {
			m, _ := filepath.Glob(filepath.Join(dir, pat))
			out = append(out, m...)
		}
	}
	return out
}

func newestPerTarget(paths []string) []string {
	best := map[string]string{}
	for _, p := range paths {
		t := targetOf(p)
		if cur, ok := best[t]; !ok || mtime(p).After(mtime(cur)) {
			best[t] = p
		}
	}
	out := make([]string, 0, len(best))
	for _, p := range best {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// ProfilePaths is one isolated ratchet record.
//
// An experiment gets its own baseline, series and history, so a throwaway
// campaign cannot contaminate the committed record -- and cannot be
// contaminated by it. Setting the three separately is possible and is how it
// went wrong: they have to move together, and three env vars is three chances
// to forget one and write half an experiment into the real record.
type ProfilePaths struct {
	Baseline, Series, History, Acks string

	// Own says the baseline path is the profile's, not one the caller named.
	// A missing file then means "this profile is new"; a missing file at a
	// path someone typed means they typed it wrong, and silently starting
	// empty there would print an empty record as though it were the answer.
	Own bool
}

// LoadBaseline reads the profile's baseline, treating a missing file as a new
// profile only when the path is the profile's own.
func (p ProfilePaths) LoadBaseline(path string) (ratchet.Baseline, error) {
	b, err := ratchet.Load(path)
	if err != nil && os.IsNotExist(err) && p.Own && path == p.Baseline {
		return ratchet.Baseline{Version: 1, Tolerance: ratchet.DefaultTolerance}, nil
	}
	return b, err
}

// profilePaths resolves a profile. "main" is the committed record.
//
// The environment still wins where set, because the tests point the checker at
// a throwaway directory and must keep working without knowing about profiles.
func profilePaths(r paths.Roots, profile string) (ProfilePaths, error) {
	home, err := r.NeedHome()
	if err != nil {
		return ProfilePaths{}, err
	}
	scripts := filepath.Join(home, "scripts")
	p := ProfilePaths{
		Baseline: filepath.Join(scripts, "ratchet-baseline.json"),
		Series:   filepath.Join(scripts, "ratchet-series.jsonl"),
		History:  filepath.Join(scripts, "ratchet-history.jsonl"),
		// The accept-list is NOT per profile. It is knowledge about
		// PostgreSQL -- which sites are -fwrapv and defined to wrap -- and
		// that does not change because an experiment is running.
		Acks: filepath.Join(scripts, "known-starved.tsv"),
	}
	if profile != "" && profile != "main" {
		d := filepath.Join(scripts, "ratchets", profile)
		if err := os.MkdirAll(d, 0o755); err != nil {
			return ProfilePaths{}, err
		}
		p.Baseline = filepath.Join(d, "baseline.json")
		p.Series = filepath.Join(d, "series.jsonl")
		p.History = filepath.Join(d, "history.jsonl")
	}
	p.Own = true
	p.Baseline = env("RATCHET_BASELINE", p.Baseline)
	p.Series = env("RATCHET_SERIES", p.Series)
	p.History = env("RATCHET_HISTORY", p.History)
	return p, nil
}

// workspaceRef is the ref a workspace tracks, from its own conf.
//
// NOT BUILD-INFO's server_tree, which describes how the server half was
// compiled ("uninstrumented gcc, --enable-cassert") and is not a ref at all.
// Printing it under a column headed "ref" is the kind of mislabel a reader
// cannot catch, because both are plausible strings in that position.
func workspaceRef(wsRoot, ws string) string {
	b, err := os.ReadFile(filepath.Join(wsRoot, ws, "workspace.conf"))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "ref="); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// workspacePatches names the patches a workspace applies, from its own conf.
// workspaceOrioleSHA is the OrioleDB commit a workspace was built from.
//
// From workspace.conf, which is where it is written. BUILD-INFO.json carries
// only a boolean saying whether the build is an OrioleDB one.
//
// Nine workspaces on disk hold `orioledb_sha=` with nothing after it, and an
// older driver wrote the literal `(not built)`. Neither is a commit, and a
// placeholder that reaches a provenance table is worse than a blank, so only
// hex counts.
func workspaceOrioleSHA(wsRoot, ws string) string {
	b, err := os.ReadFile(filepath.Join(wsRoot, ws, "workspace.conf"))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		v, ok := strings.CutPrefix(strings.TrimSpace(line), "orioledb_sha=")
		if !ok {
			continue
		}
		if v = strings.TrimSpace(v); isHex(v) && v != "" {
			return v
		}
		return ""
	}
	return ""
}

// isHex reports whether every rune is a hex digit. An empty string is not a
// commit, and neither is "(not built)".
func isHex(s string) bool {
	for _, c := range s {
		if !strings.ContainsRune("0123456789abcdef", c) {
			return false
		}
	}
	return true
}

// selectTargets applies a workspace's targets= key, and says what it dropped.
//
// The key has been written into every workspace.conf since the shell driver,
// described there as "targets to run when you ask for all", and read by
// nothing. All 59 on this host are empty, so it has never yet mattered -- and
// the first person to fill one in would have been ignored without a word.
//
// LOUD when a name does not exist. A config asking for a target that was not
// built is a mistake somebody wants to hear about, and the alternative is a
// campaign quietly narrower than the one that was asked for.
func selectTargets(c workspace.Conf, built []string) []string {
	sel, missing := build.Selected(built, c.Get("targets"))
	if len(missing) > 0 {
		fmt.Fprintf(os.Stderr,
			"pgfuzz: %s: targets= names %d target(s) that were not built: %s\n",
			c.Name, len(missing), strings.Join(missing, " "))
	}
	return sel
}

func workspacePatches(wsRoot, ws string) string {
	b, err := os.ReadFile(filepath.Join(wsRoot, ws, "workspace.conf"))
	if err != nil {
		return ""
	}
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(line, "patch="); ok {
			for _, p := range strings.Fields(v) {
				out = append(out, filepath.Base(p))
			}
		}
	}
	return strings.Join(out, " ")
}

// cmdPin reads, checks, or moves the substrate pin.
func cmdPin(argv []string) int {
	fs := flag.NewFlagSet("pin", flag.ExitOnError)
	check := fs.Bool("check", false, "exit 1 if the substrate does not match")
	update := fs.Bool("update", false, "move the pin to what this machine has")
	reason := fs.String("reason", "", "why the pin is moving; required by -update")
	pgRef := fs.String("pg", "", "also pin this PostgreSQL ref at its current commit")
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	if err := fs.Parse(argv); err != nil {
		return 2
	}
	r := paths.Resolve()
	home, err := r.NeedHome()
	if err != nil {
		fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
		return 2
	}

	// PINNING A POSTGRESQL REF, which is opt-in per ref. A ref that is not
	// listed still tracks its branch, so a HEAD run stays possible and stays
	// honest about being one.
	if *pgRef != "" {
		pins, err := archive.ReadPGPin(home)
		if err != nil {
			fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
			return 2
		}
		pgRepo := filepath.Join(r.Cache, "postgres")
		sha, err := archive.ResolvePG(pgRepo, *pgRef)
		if err != nil {
			fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
			return 2
		}
		if was, ok := pins[*pgRef]; ok && was != sha && *reason == "" {
			fmt.Fprintf(os.Stderr,
				"pgfuzz: %s is already pinned to %s; moving it needs -reason,\n"+
					"  because every fingerprint after the move differs from every one before\n",
				*pgRef, was[:12])
			return 2
		}
		pins[*pgRef] = sha
		if err := pins.Write(home); err != nil {
			fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
			return 2
		}
		fmt.Printf("pinned %s at %s\n", *pgRef, sha)
		return 0
	}

	if *update {
		// A reason, for the same rule the ratchet applies to lowering a floor:
		// every fingerprint after this differs from every one before it, and a
		// change that large should say why in the commit that makes it.
		if *reason == "" {
			fmt.Fprintln(os.Stderr, "pgfuzz: -update needs -reason. Moving the pin makes every\n"+
				"  run before it incomparable with every run after it.")
			return 2
		}
		cur, err := archive.CurrentPin(home, r.OSSFuzz())
		if err != nil {
			fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
			return 2
		}
		old, _ := archive.ReadPin(home)
		if err := cur.Write(home); err != nil {
			fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
			return 2
		}
		fmt.Printf("  pin moved -- %s\n", *reason)
		fmt.Printf("    commit      %s -> %s\n", shortOr(old.Commit), shortOr(cur.Commit))
		fmt.Printf("    base image  %s -> %s\n", shortOr(old.BaseImage), shortOr(cur.BaseImage))
		fmt.Printf("  commit %s with the reason above.\n", archive.PinFile)
		return 0
	}

	pin, err := archive.ReadPin(home)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
		return 2
	}
	bad := pin.Check(r.OSSFuzz())
	if len(bad) == 0 {
		fmt.Printf("  substrate matches the pin\n    commit      %s\n    base image  %s\n",
			pin.Commit, pin.BaseImage)
		return 0
	}
	fmt.Fprintf(os.Stderr, "  the substrate does not match %s:\n", archive.PinFile)
	for _, m := range bad {
		fmt.Fprintln(os.Stderr, m)
	}
	if *check {
		return 1
	}
	return 1
}

func shortOr(s string) string {
	if s == "" {
		return "(unset)"
	}
	if len(s) > 48 {
		return s[:48] + "..."
	}
	return s
}

// cmdReown hands build outputs back to the host user.
//
// Builds made before Reown became part of the build path are still root-owned,
// and there is a lot of them: the coverage source copy alone left 437,176 files
// across this checkout, some of them mode 0700, so the host user could not even
// traverse the tree to measure it. This is the one-off repair, and it stays
// because any build restored from an archive arrives the same way.
func cmdReown(argv []string) int {
	fs := flag.NewFlagSet("reown", flag.ExitOnError)
	ws := fs.String("w", "", "workspace name or path")
	all := fs.Bool("all", false, "every workspace")
	dry := fs.Bool("n", false, "list what would be repaired, change nothing")
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	if err := fs.Parse(argv); err != nil {
		return 2
	}
	if fs.NArg() == 0 && (*ws == "") == !*all {
		fs.Usage()
		return 2
	}

	r := paths.Resolve()

	// Positional paths are repaired as given. They are how the leftovers that
	// are not workspaces get reached -- the .cov-parallel-* directories the
	// pre-Go coverage scripts left behind, which are still read as evidence by
	// FindProfiles and so must be repaired rather than deleted.
	if fs.NArg() > 0 {
		return reownPaths(fs.Args(), *dry)
	}

	var dirs []string
	if *all {
		entries, err := os.ReadDir(r.WS)
		if err != nil {
			fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
			return 2
		}
		for _, e := range entries {
			if e.IsDir() && fileExists(filepath.Join(r.WS, e.Name(), "workspace.conf")) {
				dirs = append(dirs, filepath.Join(r.WS, e.Name()))
			}
		}
	} else {
		d := *ws
		if !filepath.IsAbs(d) && !fileExists(filepath.Join(d, "workspace.conf")) {
			d = r.Workspace(*ws)
		}
		dirs = append(dirs, d)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var repaired, failed int
	for _, d := range dirs {
		conf, err := workspace.Load(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%-24s skipped: %v\n", filepath.Base(d), err)
			continue
		}
		// The corpus is not in this list on purpose: it is millions of files
		// in the larger workspaces, and `pgfuzz corpus -repair` is the tool
		// for it. Everything else a container writes into is here.
		var cand []string
		builds, _ := os.ReadDir(filepath.Join(d, "builds"))
		for _, b := range builds {
			if b.IsDir() {
				cand = append(cand, filepath.Join(d, "builds", b.Name()))
			}
		}
		cand = append(cand, filepath.Join(d, "lineage"), filepath.Join(d, "runtmp"),
			filepath.Join(d, "reprotmp"), filepath.Join(d, ".union"))
		// artifacts.pre-* are the pre-consolidation artifact backups; they
		// hold reproducers, so they are repaired rather than left alone.
		if pre, err := filepath.Glob(filepath.Join(d, "artifacts*")); err == nil {
			cand = append(cand, pre...)
		}

		for _, out := range cand {
			if _, err := os.Stat(out); err != nil {
				continue
			}
			n := foreignCount(out)
			if n == 0 {
				continue
			}
			fmt.Printf("%-24s %-40s %d files\n", filepath.Base(d), filepath.Base(out), n)
			if *dry {
				repaired++
				continue
			}
			if err := build.Reown(ctx, "gcr.io/oss-fuzz/"+conf.Project, out); err != nil {
				fmt.Fprintf(os.Stderr, "  %v\n", err)
				failed++
				continue
			}
			if left := foreignCount(out); left != 0 {
				fmt.Fprintf(os.Stderr, "  %d files still not owned by the host user\n", left)
				failed++
				continue
			}
			repaired++
		}
	}
	verb := "repaired"
	if *dry {
		verb = "would repair"
	}
	fmt.Printf("\n%s %d build(s), %d failed\n", verb, repaired, failed)
	if failed > 0 {
		return 1
	}
	return 0
}

// foreignCount counts what the host user does not own. A directory it cannot
// even read counts as one, which is the point: an unreadable tree is exactly
// the thing being repaired, and reporting zero for it would be a lie.
func foreignCount(root string) int {
	me := os.Getuid()
	n := 0
	filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			n++
			return nil
		}
		if info, err := d.Info(); err == nil {
			if st, ok := info.Sys().(*syscall.Stat_t); ok && int(st.Uid) != me {
				n++
			}
		}
		return nil
	})
	return n
}

// reownPaths repairs directories named directly, with no workspace around
// them. The image is only a vehicle for the binary, so any project image will
// do; base-runner is the one guaranteed to be present.
func reownPaths(paths []string, dry bool) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var repaired, failed int
	for _, p := range paths {
		n := foreignCount(p)
		if n == 0 {
			continue
		}
		fmt.Printf("%-56s %d files\n", p, n)
		if dry {
			repaired++
			continue
		}
		if err := build.Reown(ctx, "gcr.io/oss-fuzz-base/base-runner:ubuntu-24-04", p); err != nil {
			fmt.Fprintf(os.Stderr, "  %v\n", err)
			failed++
			continue
		}
		if left := foreignCount(p); left != 0 {
			fmt.Fprintf(os.Stderr, "  %d files still not owned by the host user\n", left)
			failed++
			continue
		}
		repaired++
	}
	verb := "repaired"
	if dry {
		verb = "would repair"
	}
	fmt.Printf("\n%s %d path(s), %d failed\n", verb, repaired, failed)
	if failed > 0 {
		return 1
	}
	return 0
}

// buildIntoCampaign builds one workspace into the campaign's own directory.
//
// Run as a SUBPROCESS of this same binary rather than by calling cmdBuild:
// cmdBuild writes progress to os.Stderr from twenty places, and a campaign needs
// each workspace's build in its own file so a dashboard can say which build is
// running now. Re-executing ourselves is already how the in-container halves
// work, and it keeps the log honest -- everything the build printed is in it,
// in order, including whatever the container wrote.
//
// The log is teed to stderr as well, because a build that only writes to a file
// looks like a hang to whoever is watching the terminal.
func buildIntoCampaign(slugDir, ws, dest, wsDir string) error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	logPath := campaign.BuildLog(slugDir, ws)
	f, err := os.Create(logPath)
	if err != nil {
		return err
	}
	defer f.Close()

	fmt.Fprintf(os.Stderr, "==> %s: building into the campaign\n    %s\n    log %s\n",
		ws, dest, logPath)

	cmd := exec.Command(self, "build", "-w", ws, "-into", dest)
	// The campaign already holds this workspace's lock; tell the child so it
	// does not refuse itself.
	if abs, err := filepath.Abs(wsDir); err == nil {
		cmd.Env = append(os.Environ(), wslock.EnvHeld+"="+abs)
	}
	sink := io.MultiWriter(f, os.Stderr)
	cmd.Stdout, cmd.Stderr = sink, sink
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("build failed (%v); see %s", err, logPath)
	}
	return nil
}

// pluginOutcome reads back which plugins a build actually got.
//
// From the build's own log, because that is where build.sh says it -- and a
// build SUCCEEDS with plugins missing, so "what did this build contain" cannot
// be inferred from the exit code. Recording it in the manifest is what makes a
// finding attributable to a plugin set months later.
func pluginOutcome(logPath string) (built, failed []string) {
	b, err := os.ReadFile(logPath)
	if err != nil {
		return nil, nil
	}
	for _, line := range strings.Split(string(b), "\n") {
		i := strings.Index(line, "build.sh: plugins built:")
		if i < 0 || strings.HasPrefix(strings.TrimSpace(line), "+") {
			continue
		}
		rest := line[i+len("build.sh: plugins built:"):]
		okPart, failPart, _ := strings.Cut(rest, "FAILED:")
		built = strings.Fields(okPart)
		failed = strings.Fields(failPart)
	}
	return built, failed
}

// cmdClone makes a standalone copy of a campaign.
//
// A sealed campaign's corpus is HARD-LINKED to the workspace it was seeded
// from: same bytes, no second copy, independent directory entries. That is
// exactly right while the slug sits on the filesystem it was created on, and
// it is not a copy you can put on a memory stick -- `tar`, `rsync` and `cp`
// resolve links to real files, but only if you remember to, and a slug that
// was moved wrongly is a slug whose corpus quietly followed the workspace.
//
// So the tool does it: clone writes real files, and verifies the count rather
// than reporting success because nothing returned an error.
func cmdClone(argv []string) int {
	fs := flag.NewFlagSet("clone", flag.ExitOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	if err := fs.Parse(argv); err != nil {
		return 2
	}
	if fs.NArg() != 2 {
		fs.Usage()
		return 2
	}
	src, dst := fs.Arg(0), fs.Arg(1)
	r := paths.Resolve()
	if !filepath.IsAbs(src) && !fileExists(filepath.Join(src, "MANIFEST.json")) {
		src = filepath.Join(r.Campaigns(), src)
	}
	man, err := campaign.ReadManifest(src)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pgfuzz: %s: no campaign manifest: %v\n", src, err)
		return 2
	}
	if !man.Sealed {
		// Refused, not warned. An unsealed campaign shared the workspace
		// corpus, so what a clone would capture is whatever that corpus
		// happens to hold NOW -- not what the campaign fuzzed. Copying it
		// would produce a directory that looks reportable and is not.
		fmt.Fprintf(os.Stderr,
			"pgfuzz: %s is not sealed -- it shared its workspaces' corpora, so\n"+
				"  there is no corpus here that belongs to this campaign. Re-run it\n"+
				"  with -sealed if you need a slug you can hand to someone.\n", man.Slug)
		return 1
	}
	if _, err := os.Stat(dst); err == nil {
		fmt.Fprintf(os.Stderr, "pgfuzz: %s already exists\n", dst)
		return 2
	}

	fmt.Printf("cloning %s -> %s\n", src, dst)
	files, bytes, err := copyTreeCounted(src, dst)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
		return 1
	}
	// Counted on BOTH sides rather than trusting the walk: a copy that stopped
	// early returns no error if the error was swallowed, and a short corpus is
	// invisible in a coverage number.
	want := countTree(src)
	got := countTree(dst)
	fmt.Printf("  %d files, %s\n", files, humanBytes(bytes))
	if want != got {
		fmt.Fprintf(os.Stderr, "pgfuzz: clone is short: %d files here, %d there\n", want, got)
		return 1
	}
	fmt.Printf("  verified %d files; the clone shares nothing with this machine\n", got)
	return 0
}

func copyTreeCounted(from, to string) (files int, total int64, err error) {
	err = filepath.Walk(from, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(from, p)
		if err != nil {
			return err
		}
		d := filepath.Join(to, rel)
		switch {
		case fi.IsDir():
			return os.MkdirAll(d, fi.Mode().Perm())
		case fi.Mode()&os.ModeSymlink != 0:
			t, err := os.Readlink(p)
			if err != nil {
				return err
			}
			return os.Symlink(t, d)
		case !fi.Mode().IsRegular():
			return nil
		}
		in, err := os.Open(p)
		if err != nil {
			return err
		}
		defer in.Close()
		out, err := os.OpenFile(d, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, fi.Mode().Perm())
		if err != nil {
			return err
		}
		n, err := io.Copy(out, in)
		if cerr := out.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return err
		}
		files++
		total += n
		return nil
	})
	return files, total, err
}

func countTree(root string) int {
	n := 0
	filepath.WalkDir(root, func(_ string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			n++
		}
		return nil
	})
	return n
}

func humanBytes(n int64) string {
	const u = 1024
	if n < u {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(u), 0
	for m := n / u; m >= u; m /= u {
		div *= u
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}

// gateAfterSweep judges one workspace's round, then raises its floors.
//
// CHECK BEFORE UPDATE, always. Updating first folds the round being judged
// into the floor it is judged against, which makes a regression arithmetically
// impossible -- the gate would pass forever and say nothing.
//
// A SHORT ROUND IS NOT JUDGED. Bounding the clock must not manufacture
// findings: a workspace that got through six of its targets has not earned a
// verdict on the other seventeen. The floors are not raised either, since a
// partial round is not evidence that a higher floor is sustainable.
// gateAfterSweep runs the ratchet, unless the round cannot be judged.
//
// notJudgeable names the reason, and there is more than one. A round that
// never finished is the obvious case. The other is a round where EVERY target
// ran and one of them was stopped part-way by the disk floor: nothing above
// notices, the numbers look complete, and the ratchet reads an artificially
// low slice as a regression in the target rather than as a fact about the
// filesystem.
func gateAfterSweep(r paths.Roots, e campaign.Entry, round, jobs int, notJudgeable string) {
	if notJudgeable != "" {
		fmt.Fprintf(os.Stderr, "  gates skipped: %s\n", notJudgeable)
		return
	}
	self, err := os.Executable()
	if err != nil {
		return
	}
	run := func(what string, args ...string) int {
		cmd := exec.Command(self, args...)
		cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
		if err := cmd.Run(); err != nil {
			if ee, ok := err.(*exec.ExitError); ok {
				return ee.ExitCode()
			}
			fmt.Fprintf(os.Stderr, "  %s: %v\n", what, err)
			return -1
		}
		return 0
	}
	j := strconv.Itoa(jobs)
	if code := run("ratchet check", "ratchet", "-w", e.Dir, "-jobs", j); code == 1 {
		// Reported, not fatal. The campaign's job is to keep fuzzing; the
		// regression is a fact about this round and the series records it.
		fmt.Fprintf(os.Stderr, "  !! %s REGRESSED in round %d\n", e.Name, round)
	}
	run("ratchet update", "ratchet", "-w", e.Dir, "-update", "-jobs", j)
}

// openMaybeGzip opens a log that may or may not be compressed.
//
// `pgfuzz tidy` gzips run logs over 10 MB, so anything that reads one has to
// cope with both -- reading only plain files is how tidying a workspace
// silently emptied the census.
func openMaybeGzip(path string) (*os.File, io.Reader, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	if !strings.HasSuffix(path, ".gz") {
		return f, f, nil
	}
	zr, err := gzip.NewReader(f)
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	return f, zr, nil
}

func closeAll(r io.Reader, f *os.File) {
	if c, ok := r.(io.Closer); ok && r != io.Reader(f) {
		c.Close()
	}
	f.Close()
}

// cmdBreakdown answers "which component produced these crashes".
//
// internal/breakdown was ported faithfully -- Classify, PatchedFiles, Scan,
// ComponentsOf, the bld/ fix, the touch-every-component crediting -- and then
// imported by nothing at all. The question the workspace exists to answer had
// no way to be asked, and finalreport's component table rendered from whatever
// the deleted Python had last appended.
//
// PER TARGET AND PER COMPONENT, because a single count per component cannot
// say whether one target found everything. "A patched tree plus every plugin"
// is not one thing.
func cmdBreakdown(argv []string) int {
	fs := flag.NewFlagSet("breakdown", flag.ExitOnError)
	ws := fs.String("w", "", "workspace")
	asJSON := fs.Bool("json", false, "emit the table as JSON")
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	if err := fs.Parse(argv); err != nil || *ws == "" {
		fs.Usage()
		return 2
	}
	// A WORKSPACE OR A SEALED CAMPAIGN'S COPY OF ONE.
	//
	// Since a sealed campaign owns its artifacts, the directory holding them
	// is campaigns/<slug>/ws/<name>/ and carries no workspace.conf. Refusing
	// that would mean the breakdown could not be asked about exactly the runs
	// worth asking about.
	dir, c, _, err := openWS(*ws)
	if err != nil {
		if d, derr := filepath.Abs(*ws); derr == nil && fileExists(filepath.Join(d, "artifacts")) {
			dir, c.Name = d, filepath.Base(d)
		} else {
			fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
			return 2
		}
	}

	table := breakdown.Scan(dir, nil)
	if len(table) == 0 {
		// NOT a pass. A breakdown with nothing in it means no artifact carried
		// an attributable frame, which is a different statement from "no
		// component was involved" -- and the second is what an empty table
		// looks like.
		fmt.Fprintf(os.Stderr,
			"pgfuzz: no attributable frames under %s/artifacts -- nothing to break down\n", dir)
		return 2
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return jsonExit(enc.Encode(struct {
			Workspace  string                    `json:"workspace"`
			Components []string                  `json:"components"`
			Table      map[string]map[string]int `json:"table"`
		}{c.Name, breakdown.ComponentsOf(dir), table}))
	}

	// COMPONENT x TARGET, the orientation the old table had: the question is
	// "which component did this target reach", and a single count per
	// component cannot say whether one target found everything.
	// Scan returns component -> target -> count.
	comps := make([]string, 0, len(table))
	targets := map[string]bool{}
	for comp, per := range table {
		comps = append(comps, comp)
		for t := range per {
			targets[t] = true
		}
	}
	sort.Strings(comps)
	cols := make([]string, 0, len(targets))
	for t := range targets {
		cols = append(cols, t)
	}
	sort.Strings(cols)

	fmt.Printf("%-22s", "component")
	for _, t := range cols {
		fmt.Printf(" %10s", tui.Code(t))
	}
	fmt.Println("   total")
	for _, comp := range comps {
		fmt.Printf("%-22s", clip(comp, 22))
		total := 0
		for _, t := range cols {
			n := table[comp][t]
			total += n
			if n > 0 {
				fmt.Printf(" %10d", n)
			} else {
				fmt.Printf(" %10s", ".")
			}
		}
		fmt.Printf(" %7d\n", total)
	}

	return 0
}

func jsonExit(err error) int {
	if err != nil {
		fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
		return 1
	}
	return 0
}

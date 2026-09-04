package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"strings"

	"pgfuzz/internal/build"
	"pgfuzz/internal/fuzz"
	"pgfuzz/internal/source"
	"pgfuzz/internal/wslock"
)

// cmdRegress runs PostgreSQL's own suite against a workspace's patched tree.
//
// THE PATCH IS THE THING UNDER TEST. The only check on a workspace patch is
// that it applied without leaving a .rej -- which catches a patch that does not
// fit and says nothing about whether the tree still behaves as PostgreSQL's own
// tests say it should. A patch that changes planner behaviour rewrites the
// expected output of dozens of core regression tests as a consequence, and "it
// compiled" cannot see any of that.
func cmdRegress(argv []string) int {
	fs := flag.NewFlagSet("regress", flag.ExitOnError)
	ws := fs.String("w", "", "workspace whose patched tree to check")
	work := fs.String("work", "", "scratch directory (default: <ws>/regress)")
	image := fs.String("image", "", "image with the toolchain (default: the workspace's builder)")
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
	if *work == "" {
		*work = filepath.Join(dir, "regress")
	}
	if *image == "" {
		*image = "gcr.io/oss-fuzz/" + c.Project
	}

	// A DISK PREFLIGHT, because this builds a whole second PostgreSQL.
	if err := wslock.NeedDisk(dir, fuzz.DefaultPreflightGB, "a regression run"); err != nil {
		fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
		return 2
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// EXPORTED HERE, not borrowed from the build.
	//
	// `pgfuzz build` deletes its export afterwards -- 2.6 GB a workspace of
	// dead weight, re-exported in seconds -- so a regression run cannot rely
	// on one being there. It makes its own from the same ref and applies the
	// same patch series, which is what the shell did.
	src := filepath.Join(*work, "src")
	if err := os.RemoveAll(src); err != nil {
		fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
		return 2
	}
	repo := source.Repo{Dir: filepath.Join(r.Cache, "postgres")}
	fmt.Fprintf(os.Stderr, "==> regression suite for %s\n    ref   %s\n    work  %s\n",
		c.Name, c.Ref, *work)
	short, _, err := repo.Export(ctx, c.Ref, src, os.Stderr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
		return 2
	}
	fmt.Fprintf(os.Stderr, "    tree  %s\n", short)

	// THE SAME .rej GATE the build uses. A half-patched tree would pass the
	// suite for a tree nobody is running.
	if applied, err := build.ApplyPatches(src, strings.Fields(c.Get("patch")), os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
		return 2
	} else if len(applied) > 0 {
		fmt.Fprintf(os.Stderr, "    patch %s\n", strings.Join(applied, " "))
	}
	if c.Get("patch") == "" {
		// SAID, because a suite passing against an unpatched tree proves
		// nothing about a patch and reads exactly like one that does.
		fmt.Fprintln(os.Stderr,
			"    patch (none -- this workspace applies no patch, so the suite"+
				" is checking upstream against itself)")
	}

	res, err := build.Regress(ctx, build.RegressRequest{
		Src: src, Work: *work, Image: *image, Stream: os.Stderr,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
		return 2
	}
	if res.Failed == 0 {
		fmt.Printf("\nall %d tests passed  %s\n", res.Passed, c.Name)
		return 0
	}
	// NAMED, not counted. "3 of 215 failed" sends somebody to a log to find
	// out which three, and which three is the whole answer.
	fmt.Printf("\n%d of %d tests FAILED  %s\n", res.Failed, res.Passed+res.Failed, c.Name)
	for _, t := range res.FailedTests {
		fmt.Printf("  %s\n", t)
	}
	fmt.Printf("full output: %s\n", res.CheckLog)
	return 1
}

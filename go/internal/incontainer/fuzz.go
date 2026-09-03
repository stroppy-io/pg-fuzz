package incontainer

import (
	"fmt"
	"os"
	"path/filepath"
)

// Fuzz is the in-container half of a fuzzing slice.
//
// It replaces a generated shell script that did exactly this: mount the
// overlay, run OSS-Fuzz's run_fuzzer, tee the output to a bind mount, and
// return the fuzzer's exit code rather than tee's. That last detail was a
// PIPESTATUS reference in the shell -- correct, and the kind of thing that is
// correct until somebody edits around it.
// Usage: _fuzz <target> <libfuzzer args...>
//
// Positional, not flags. libFuzzer's own arguments look exactly like flags --
// -max_total_time=600, -jobs=4 -- and a flag parser in front of them consumes
// the ones it recognises and rejects the rest. The mount points are fixed
// because this binary is the only thing that creates them.
func Fuzz(argv []string) int {
	if len(argv) == 0 {
		fmt.Fprintln(os.Stderr, "_fuzz: <target> [libfuzzer args...]")
		return 2
	}
	target := argv[0]
	if err := MountOverlay("/out-lower", "/run-ovl/upper", "/run-ovl/work", "/out"); err != nil {
		fmt.Fprintf(os.Stderr, "_fuzz: %v\n", err)
		return 2
	}
	code, err := Tee(filepath.Join("/run-ovl", "run.log"), "run_fuzzer", argv...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "_fuzz: %v\n", err)
		return 2
	}
	// The corpus mount is included, and the reasoning that first left it out
	// was wrong. It was excluded as "millions of files in the larger
	// workspaces" -- but the container mounts ONE TARGET's corpus, not the
	// workspace's, so the walk is a fraction of that and costs a fraction of a
	// second. Leaving it root-owned had a second cost that only showed up
	// later: fs.protected_hardlinks forbids linking to a file you do not own,
	// so a sealed campaign could not hard-link its corpus and silently fell
	// back to copying every input.
	handBack("/lineage", "/run-ovl", corpusMount(argv[0]))
	_ = target
	return code
}

// handBack gives the small directories this container writes into back to the
// host user, so the run does not leave root-owned files behind.
//
// The corpus is deliberately NOT in this list. It is millions of files in the
// larger workspaces and walking it every slice would cost more than the repair
// is worth; `pgfuzz corpus -repair` exists for that and runs when it is wanted.
// The callers pass small, per-run directories: the lineage TSVs and the overlay
// scratch holding run.log for a fuzzing slice, the llvm-cov staging directory
// for a coverage union.
func handBack(dirs ...string) {
	spec := os.Getenv("PGFUZZ_UID")
	if spec == "" {
		return
	}
	var uid, gid int
	if _, err := fmt.Sscanf(spec, "%d:%d", &uid, &gid); err != nil {
		fmt.Fprintf(os.Stderr, "_fuzz: PGFUZZ_UID=%q: %v\n", spec, err)
		return
	}
	for _, d := range dirs {
		if _, err := os.Stat(d); err != nil {
			continue
		}
		if n, err := Chown(d, uid, gid, true); err != nil || n > 0 {
			fmt.Fprintf(os.Stderr, "_fuzz: handing back %s: %d entries failed\n", d, n)
		}
	}
}

// corpusMount is where fuzz.Run bind-mounts this target's corpus.
func corpusMount(target string) string { return "/tmp/" + target + "_corpus" }

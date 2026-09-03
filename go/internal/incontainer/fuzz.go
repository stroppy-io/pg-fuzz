package incontainer

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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
	// PROCESSOR SECONDS, read from inside while the cgroup still exists.
	//
	// The containers are --rm, so the counter dies with them: the old sampler
	// polled from the host mid-slice for exactly that reason. Reading it here,
	// after run_fuzzer returns and before the container exits, gets the whole
	// slice in one number and needs no sampler at all.
	//
	// This is not secs x jobs. That is what the slice was ALLOWED; the
	// postmaster-backed targets spend most of a slice waiting rather than
	// computing, so the two differ by more than an order of magnitude and only
	// one of them is work done. The report quotes the wrong one without it.
	// THE PER-WORKER LOGS, before the overlay is thrown away.
	//
	// Under -jobs>1 libFuzzer forks, and each worker writes fuzz-<i>.log in
	// its working directory rather than onto stdout. The interesting lines --
	// the execution counter, INITED, and the assertion text -- often exist
	// ONLY there: 2,708 of 3,450 crashing runs in one campaign left an
	// assertion with no assertion text, because the next run clobbered them.
	// libFuzzer also deletes its own once it has printed them, so this is the
	// only chance.
	collectWorkerLogs("/run-ovl")

	writeCPUSeconds("/run-ovl/run.cpu")

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

// writeCPUSeconds records this container's processor time.
//
// cgroup v2 first, then v1. A missing counter writes nothing rather than a
// zero: the reader treats absence as "not measured" and zero as "measured no
// work", and those must not be confused.
func writeCPUSeconds(path string) {
	if b, err := os.ReadFile("/sys/fs/cgroup/cpu.stat"); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if v, ok := strings.CutPrefix(line, "usage_usec "); ok {
				if us, err := strconv.ParseFloat(strings.TrimSpace(v), 64); err == nil {
					os.WriteFile(path, []byte(strconv.FormatFloat(us/1e6, 'f', 2, 64)), 0o644)
					return
				}
			}
		}
	}
	if b, err := os.ReadFile("/sys/fs/cgroup/cpuacct/cpuacct.usage"); err == nil {
		if ns, err := strconv.ParseFloat(strings.TrimSpace(string(b)), 64); err == nil {
			os.WriteFile(path, []byte(strconv.FormatFloat(ns/1e9, 'f', 2, 64)), 0o644)
		}
	}
}

// collectWorkerLogs moves libFuzzer's per-worker logs somewhere durable.
//
// Kept as separate files rather than concatenated: the parent log repeats what
// a worker printed, so merging them double-counts every execution total the
// ratchet then reads.
func collectWorkerLogs(dst string) {
	m, _ := filepath.Glob("fuzz-*.log")
	if len(m) == 0 {
		// run_fuzzer works out of $OUT; look there too.
		m, _ = filepath.Glob("/out/fuzz-*.log")
	}
	for _, p := range m {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		os.WriteFile(filepath.Join(dst, filepath.Base(p)), b, 0o644)
	}
}

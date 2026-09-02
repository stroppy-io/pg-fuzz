package incontainer

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// Signal implements `_signal <comm> [SIGNAL]`: send a signal to processes whose
// comm matches exactly, from inside the container.
//
// This is the container half of the hang watchdog, and it exists because
// SIGKILL is the one exit path where libFuzzer prints NOTHING. Every other
// route -- interrupt, crash, timeout, normal exit -- runs PrintFinalStats()
// first. A target killed outright therefore contributes an execution count
// scraped from its progress lines and no throughput figure, which is exactly
// how seven of forty-six ratchet floors ended up unverifiable: a floor with no
// matching rate cannot be checked against anything.
//
// The signal cannot go to the container. PID 1 is the run_fuzzer WRAPPER,
// which does not forward signals, so `docker kill --signal=TERM` leaves the
// fuzzer running untouched -- measured, not assumed. It has to reach the fuzzer
// process itself, which means a process INSIDE the container has to find it.
func Signal(argv []string) int {
	if len(argv) < 1 {
		fmt.Fprintln(os.Stderr, "usage: _signal <comm> [TERM|KILL|INT]")
		return 2
	}
	sig := syscall.SIGTERM
	if len(argv) > 1 {
		switch strings.TrimPrefix(strings.ToUpper(argv[1]), "SIG") {
		case "TERM":
			sig = syscall.SIGTERM
		case "KILL":
			sig = syscall.SIGKILL
		case "INT":
			sig = syscall.SIGINT
		case "ABRT":
			sig = syscall.SIGABRT
		default:
			fmt.Fprintf(os.Stderr, "_signal: unknown signal %q\n", argv[1])
			return 2
		}
	}

	// Exact comm match, the way `pgrep -x` matches: a substring match would
	// also hit the wrapper, and signalling the wrapper is the no-op this
	// whole path exists to avoid.
	want := argv[0]
	if len(want) > 15 {
		want = want[:15] // /proc/PID/comm is truncated to TASK_COMM_LEN-1
	}
	ents, err := os.ReadDir("/proc")
	if err != nil {
		fmt.Fprintf(os.Stderr, "_signal: %v\n", err)
		return 1
	}
	sent := 0
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == os.Getpid() {
			continue
		}
		b, err := os.ReadFile(filepath.Join("/proc", e.Name(), "comm"))
		if err != nil || strings.TrimSpace(string(b)) != want {
			continue
		}
		if err := syscall.Kill(pid, sig); err == nil {
			sent++
		}
	}
	if sent == 0 {
		fmt.Fprintf(os.Stderr, "_signal: no process named %q\n", want)
		return 1
	}
	fmt.Printf("signalled %d process(es) named %s\n", sent, want)
	return 0
}

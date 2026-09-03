package fuzz

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// ReapOwn kills the containers THIS process started.
//
// KILLING THE CLIENT IS NOT KILLING THE CONTAINER. `docker run` is a client;
// the container is a child of dockerd. Ctrl-C, a deadline, or any early return
// takes down the client and leaves the fuzzer running -- the tool's own stop
// command records the consequence, "eighteen containers kept fuzzing" -- and
// they keep writing into a corpus nobody is watching, holding the workspace
// lock's memory of a run that has ended.
//
// Scoped to this PROCESS's containers by the pid in their name, so a campaign
// shutting down cannot kill a slice another campaign is legitimately running.
func ReapOwn() int {
	out, err := exec.Command("docker", "ps", "--no-trunc", "--format", "{{.Names}}").Output()
	if err != nil {
		return 0
	}
	killed := 0
	for _, name := range strings.Fields(string(out)) {
		if !Ours(name, os.Getpid()) {
			continue
		}
		if exec.Command("docker", "kill", name).Run() == nil {
			killed++
		}
	}
	return killed
}

// Ours reports whether a container name was started by this pid.
//
// SCOPED TO THE PID, and that is the whole safety property: fuzz.Run names its
// containers pgfuzz-run-<workspace>-<target>-<pid>, so a campaign shutting
// down kills its own slices and not the ones another campaign is legitimately
// running. Matching on the prefix alone would make any interrupt a
// fleet-wide stop.
func Ours(name string, pid int) bool {
	return strings.HasPrefix(name, "pgfuzz-run-") &&
		strings.HasSuffix(name, fmt.Sprintf("-%d", pid))
}

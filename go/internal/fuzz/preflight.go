package fuzz

import (
	"fmt"
	"os/exec"
	"strings"
)

// ORPHANS THIS MACHINE IS STILL RUNNING.
//
// wslock catches two campaigns on the SAME workspace. It does not catch a
// fuzzer left over from a previous run that is still writing into a workspace
// the new campaign is about to measure -- and that is the case the shell's
// preflight was written for, after a monitor went unnoticed for 2d19h.
//
// The symptom is not a crash. The old process keeps growing a corpus and
// writing artifacts while the new campaign measures the same directories, so
// the new run's numbers include work it did not do, and its ratchet floors
// rise on the strength of them.

// Orphan is a container this machine is running that no live driver owns.
type Orphan struct {
	Name      string
	Workspace string
	PID       int
}

// Orphans lists fuzzing containers whose starting process is gone.
//
// fuzz.Run names its containers pgfuzz-run-<workspace>-<target>-<pid>, so the
// owner is in the name: a container whose pid no longer exists was started by
// a run that has since died, and nothing will ever stop it.
func Orphans(alive func(int) bool) ([]Orphan, error) {
	out, err := exec.Command("docker", "ps", "--no-trunc", "--format", "{{.Names}}").Output()
	if err != nil {
		// A FAILED LOOK IS NOT AN EMPTY ANSWER, and this one is load-bearing:
		// reporting "no orphans" because docker could not be reached is how a
		// campaign starts on top of one.
		return nil, fmt.Errorf("cannot list containers: %w", err)
	}
	var res []Orphan
	for _, name := range strings.Fields(string(out)) {
		rest, ok := strings.CutPrefix(name, "pgfuzz-run-")
		if !ok {
			continue
		}
		i := strings.LastIndex(rest, "-")
		if i <= 0 {
			continue
		}
		pid := 0
		fmt.Sscanf(rest[i+1:], "%d", &pid)
		if pid == 0 || alive(pid) {
			continue
		}
		// Drop the pid, then the target, to leave the workspace.
		ws := rest[:i]
		if j := strings.LastIndex(ws, "-"); j > 0 {
			ws = ws[:j]
		}
		res = append(res, Orphan{Name: name, Workspace: ws, PID: pid})
	}
	return res, nil
}

// DescribeOrphans is a message naming what has to go, or "".
func DescribeOrphans(os []Orphan) string {
	if len(os) == 0 {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%d fuzzing container(s) are running with no live driver:\n", len(os))
	for _, o := range os {
		fmt.Fprintf(&b, "  %s  (workspace %s, started by pid %d, which is gone)\n",
			o.Name, o.Workspace, o.PID)
	}
	b.WriteString("  They are still writing into those workspaces, so a campaign\n")
	b.WriteString("  measuring them would count work it did not do.\n")
	b.WriteString("  Stop them with: docker stop <name>")
	return b.String()
}

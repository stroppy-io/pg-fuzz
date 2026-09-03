package tui

import (
	"os/exec"
	"strings"
)

// DockerErr is why the last look at docker failed, or "".
//
// A FAILED LOOK IS NOT AN EMPTY ANSWER. Returning nil on error made a fully
// busy machine read as idle, everywhere on the screen at once -- the exact
// 2026-08-22 incident the old dashboard's comment describes: "the reading was
// confident, wrong, and silent". Losing the docker group, a daemon restart, or
// a timeout all land here.
var DockerErr string

// RunningNow says which target each workspace is fuzzing this instant.
//
// From the CONTAINER NAMES, which is the only place that fact exists while a
// slice is in flight: the series records a slice when it FINISHES, so a
// dashboard built from the series alone shows a workspace as idle for the whole
// forty-five seconds it is actually working. Row.Running was declared and never
// filled, so the "fuzzing" marker never once appeared.
//
// fuzz.Run names its containers pgfuzz-run-<workspace>-<target>-<pid>. Target
// names never contain a hyphen and workspace names routinely do (gt-pg16), so
// the split is from the RIGHT: drop the pid, then take the last hyphen as the
// boundary. Splitting from the left would read "gt" as the workspace.

func RunningNow() map[string]string {
	out, err := exec.Command("docker", "ps", "--no-trunc", "--format", "{{.Names}}").Output()
	if err != nil {
		DockerErr = err.Error()
		return nil
	}
	DockerErr = ""
	res := map[string]string{}
	for _, name := range strings.Fields(string(out)) {
		rest, ok := strings.CutPrefix(name, "pgfuzz-run-")
		if !ok {
			continue
		}
		// Drop the -<pid> suffix.
		if i := strings.LastIndex(rest, "-"); i > 0 {
			rest = rest[:i]
		}
		i := strings.LastIndex(rest, "-")
		if i <= 0 {
			continue
		}
		res[rest[:i]] = rest[i+1:]
	}
	return res
}

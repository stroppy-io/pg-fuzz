package tui

import (
	"os/exec"
	"strings"
)

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
		return nil
	}
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

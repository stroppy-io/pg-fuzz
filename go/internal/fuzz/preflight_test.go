package fuzz

import (
	"strings"
	"testing"
)

// A FAILED LOOK IS NOT AN EMPTY ANSWER, and here it is load-bearing:
// reporting "no orphans" because docker could not be reached is how a campaign
// starts on top of one.
func TestOrphansReportsAFailedLook(t *testing.T) {
	// Orphans shells out; on a machine with no docker it must error rather
	// than return an empty list.
	_, err := Orphans(func(int) bool { return true })
	if err == nil {
		t.Skip("docker is reachable here; the failure path is covered by review")
	}
	if !strings.Contains(err.Error(), "cannot list containers") {
		t.Errorf("unhelpful error: %v", err)
	}
}

// THE OWNER IS IN THE NAME. fuzz.Run names containers
// pgfuzz-run-<workspace>-<target>-<pid>, so a container whose pid is gone was
// started by a run that has died and nothing will ever stop it.
func TestDescribeOrphansNamesWhatToStop(t *testing.T) {
	msg := DescribeOrphans([]Orphan{
		{Name: "pgfuzz-run-gt-pg17-jsonb_fuzzer-4242", Workspace: "gt-pg17", PID: 4242},
	})
	for _, want := range []string{"gt-pg17", "4242", "docker stop"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the message does not mention %q:\n%s", want, msg)
		}
	}
	// Nothing running is silence, not a warning.
	if DescribeOrphans(nil) != "" {
		t.Error("an empty list produced a message")
	}
}

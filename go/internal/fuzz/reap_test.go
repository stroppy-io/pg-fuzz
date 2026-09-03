package fuzz

import "testing"

// Killing the docker CLIENT is not killing the container -- it is a child of
// dockerd, so an interrupt leaves the fuzzer running. The tool's own stop
// command records the consequence: "eighteen containers kept fuzzing".
//
// The matching must be scoped to THIS pid, or a campaign shutting down would
// kill slices another campaign is legitimately running.
func TestOursMatchesOnlyThisProcessesContainers(t *testing.T) {
	const me = 4242
	for _, c := range []struct {
		name string
		want bool
		why  string
	}{
		{"pgfuzz-run-gt-pg17-xlogreader_fuzzer-4242", true, "ours"},
		{"pgfuzz-run-gt-pg17-xlogreader_fuzzer-9999", false, "another campaign's slice"},
		{"pgfuzz-run-w-t-42421", false, "a pid that merely starts with ours"},
		{"pgfuzz-cov-gt-pg17-4242", false, "not a fuzzing slice"},
		{"unrelated-container", false, "nothing to do with us"},
		{"pgfuzz-run-gt-pg17-xlogreader_fuzzer", false, "no pid at all"},
	} {
		if got := Ours(c.name, me); got != c.want {
			t.Errorf("Ours(%q) = %v, want %v (%s)", c.name, got, c.want, c.why)
		}
	}
}

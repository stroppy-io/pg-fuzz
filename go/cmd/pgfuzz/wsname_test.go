package main

import "strings"
import "testing"

// A WORKSPACE NAME BECOMES A DOCKER TAG.
//
// The project is "pgfuzz-<name>" and helper.py builds gcr.io/oss-fuzz/<project>,
// so an uppercase letter fails twenty minutes into a build as
// `invalid tag ...: repository name must be lowercase` -- a docker USAGE
// error, surfaced as "Run 'docker build --help'", which says nothing about the
// workspace that caused it. Ten CI items died on exactly that.
func TestWorkspaceNameMustBeAUsableTag(t *testing.T) {
	if got := badWorkspaceName("ci-REL_17_STABLE-address"); got == "" {
		t.Error("an uppercase name was accepted; docker will refuse it later")
	} else if !strings.Contains(got, "lowercase") {
		t.Errorf("the reason is not stated: %s", got)
	}
	// And it suggests the fix, because the reader's next question is "then
	// what should I call it".
	if got := badWorkspaceName("ci-REL_17-address"); !strings.Contains(got, "ci-rel_17-address") {
		t.Errorf("no suggested name: %s", got)
	}

	for _, ok := range []string{"gt-pg17", "vfy-pg17", "pg17-10-ext-all-add", "a.b_c-1"} {
		if got := badWorkspaceName(ok); got != "" {
			t.Errorf("badWorkspaceName(%q) = %q, want it accepted", ok, got)
		}
	}
	for _, bad := range []string{"", "has space", "slash/name", "star*"} {
		if badWorkspaceName(bad) == "" {
			t.Errorf("badWorkspaceName(%q) accepted an unusable name", bad)
		}
	}
}

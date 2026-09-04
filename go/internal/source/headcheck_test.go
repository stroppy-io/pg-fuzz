package source

import (
	"context"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func git(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

// A BUILD MUST NOT TAKE A LOCAL BRANCH THAT IS BEHIND ITS REMOTE.
//
// Resolve tries the bare ref first and a fetch advances only remote-tracking
// refs, so `ref=master` builds whatever the local branch was last set to while
// the build line calls it a moving branch as though it were HEAD. The
// documented case is a tree eleven days behind, fuzzed for a week.
func TestBehindRemoteCatchesAStaleLocalBranch(t *testing.T) {
	root := t.TempDir()
	origin := filepath.Join(root, "origin")
	clone := filepath.Join(root, "clone")

	git(t, root, "init", "-q", "-b", "master", origin)
	git(t, origin, "-c", "user.email=t@t", "-c", "user.name=t",
		"commit", "-q", "--allow-empty", "-m", "one")
	git(t, root, "clone", "-q", origin, clone)

	r := Repo{Dir: clone}
	ctx := context.Background()

	// In step: nothing to say.
	if why := r.BehindRemote(ctx, "master"); why != "" {
		t.Errorf("a branch in step reported: %s", why)
	}

	// origin moves; the clone fetches but does not merge -- the exact shape.
	git(t, origin, "-c", "user.email=t@t", "-c", "user.name=t",
		"commit", "-q", "--allow-empty", "-m", "two")
	git(t, clone, "fetch", "-q", "origin")

	why := r.BehindRemote(ctx, "master")
	if why == "" {
		t.Fatal("a stale local branch was not reported")
	}
	if !strings.Contains(why, "master") || !strings.Contains(why, "origin/master") {
		t.Errorf("the message does not name both sides: %s", why)
	}
}

// WHAT IS NOT A LOCAL BRANCH IS NOT THIS PROBLEM. An explicit origin/<x>, a
// tag or a sha resolves to exactly one thing, and refusing those would refuse
// every correctly-specified build.
func TestBehindRemoteIgnoresUnambiguousRefs(t *testing.T) {
	root := t.TempDir()
	origin := filepath.Join(root, "origin")
	clone := filepath.Join(root, "clone")
	git(t, root, "init", "-q", "-b", "master", origin)
	git(t, origin, "-c", "user.email=t@t", "-c", "user.name=t",
		"commit", "-q", "--allow-empty", "-m", "one")
	git(t, root, "clone", "-q", origin, clone)

	r := Repo{Dir: clone}
	ctx := context.Background()
	for _, ref := range []string{"origin/master", "refs/heads/master", "no-such-branch"} {
		if why := r.BehindRemote(ctx, ref); why != "" {
			t.Errorf("ref %q reported: %s", ref, why)
		}
	}
}

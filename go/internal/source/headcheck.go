package source

import (
	"context"
	"fmt"
	"strings"
)

// BehindRemote reports how a local branch differs from the remote it tracks.
//
// THE STALE-LOCAL-BRANCH REFUSAL, which the shell had and the port dropped.
//
// Resolve tries the bare ref first and only falls back to origin/<ref>, and a
// fetch advances remote-tracking refs alone. So for `ref=master` or `main` --
// which a clone materialises locally -- the build takes whatever that local
// branch was last set to, and IsMoving then prints "moving branch, this build
// is <stale sha>" as though it were HEAD. The documented case is an OrioleDB
// tree eleven days behind, fuzzed for a week as though it were current, with
// every gate downstream passing it.
//
// The PostgreSQL pin does not cover this: it is opt-in per ref and returns
// clean for anything not listed.
//
// Returns "" when the ref is not a local branch, when it has no remote
// counterpart, or when the two agree -- none of which is a problem.
func (r Repo) BehindRemote(ctx context.Context, ref string) string {
	// Only a bare branch name can have this problem. An explicit origin/<x>,
	// a tag or a sha resolves to one thing.
	if strings.Contains(ref, "/") {
		return ""
	}
	local, err := r.revParse(ctx, ref)
	if err != nil {
		return "" // not a local branch; Resolve will use origin/<ref>
	}
	remote, err := r.revParse(ctx, "origin/"+ref)
	if err != nil {
		return "" // nothing to compare against
	}
	if local == remote {
		return ""
	}
	return fmt.Sprintf(
		"local branch %s is %s but origin/%s is %s.\n"+
			"  A build from the local branch is not the tree that ref names any more.\n"+
			"  Either `git -C %s checkout %s && git merge --ff-only origin/%s`,\n"+
			"  or build origin/%s explicitly and record that as the ref.",
		ref, shortSHA(local), ref, shortSHA(remote), r.Dir, ref, ref, ref)
}

func shortSHA(s string) string {
	if len(s) > 10 {
		return s[:10]
	}
	return s
}

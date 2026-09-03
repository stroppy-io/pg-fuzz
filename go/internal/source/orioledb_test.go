package source

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func orioleRepo(t *testing.T, pgtags string) string {
	t.Helper()
	dir := t.TempDir()
	run := func(args ...string) {
		c := exec.Command("git", args...)
		c.Dir = dir
		c.Env = append(c.Environ(),
			"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t",
			"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("init", "-q", "-b", "main")
	if err := os.WriteFile(filepath.Join(dir, ".pgtags"), []byte(pgtags), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", ".pgtags")
	run("commit", "-q", "-m", "pgtags")
	return dir
}

// OrioleDB refuses to build against any patchset commit but its own, so a
// bare major is not a buildable ref -- it has to be resolved through .pgtags.
// The port dropped this, so 23 workspaces naming ref=16|17|18 could not be
// built at all.
func TestPatchsetForResolvesABareMajor(t *testing.T) {
	repo := orioleRepo(t, "16: REL_16_STABLE_orioledb\n17: patches17_2\n18: patches18_1\n")

	got, err := PatchsetFor(repo, "main", "17")
	if err != nil {
		t.Fatalf("PatchsetFor: %v", err)
	}
	if got != "patches17_2" {
		t.Errorf("major 17 resolved to %q, want patches17_2", got)
	}

	// A major the fork does not carry must fail loudly, not silently build
	// something else: build.sh keys the extension path on a file in the
	// export, so a fork-without-extension build looks exactly like a real one.
	if _, err := PatchsetFor(repo, "main", "99"); err == nil {
		t.Error("a major with no patchset resolved anyway")
	} else if !strings.Contains(err.Error(), "no PostgreSQL 99 patchset") {
		t.Errorf("unhelpful error: %v", err)
	}
}

// git fetch advances refs/remotes/origin/main and does not touch the local
// branch or the checkout, so reading .pgtags off disk uses whatever was last
// checked out by hand -- once an OrioleDB eleven days stale.
func TestPatchsetIsReadFromTheRefNotTheWorkingTree(t *testing.T) {
	repo := orioleRepo(t, "17: patches17_2\n")
	// Vandalise the working tree; the committed ref still governs.
	if err := os.WriteFile(filepath.Join(repo, ".pgtags"),
		[]byte("17: STALE_FROM_DISK\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := PatchsetFor(repo, "main", "17")
	if err != nil {
		t.Fatal(err)
	}
	if got != "patches17_2" {
		t.Errorf("read %q from the working tree; must read the ref", got)
	}
}

func TestIsBareMajor(t *testing.T) {
	for in, want := range map[string]bool{
		"16": true, "17": true, "18": true,
		"": false, "main": false, "REL_17_STABLE": false, "origin/master": false,
		"17.1": false,
	} {
		if got := IsBareMajor(in); got != want {
			t.Errorf("IsBareMajor(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestOrioleCommitIsRecorded(t *testing.T) {
	repo := orioleRepo(t, "17: patches17_2\n")
	if got := OrioleCommit(repo, "main"); got == "" {
		t.Error("no commit recorded; a fork-only build and a real OrioleDB " +
			"build would be indistinguishable afterwards")
	}
}

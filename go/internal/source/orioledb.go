package source

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// THE ORIOLEDB FLAVOUR, which the port reduced to swapping one repository.
//
// Everything else went: resolving a bare major through .pgtags, exporting the
// extension beside the fork, and recording which OrioleDB commit produced the
// build. 23 workspaces on this machine name `ref=16|17|18`, and none of them
// could be built -- `git rev-parse 17` fails against the fork, so the build
// errored out. That is at least loud.
//
// The quiet failure is worse and was one step away: build.sh keys the whole
// extension path on orioledb/orioledb.control existing in the export, so a
// bare ref that DID resolve would have produced a fork-without-extension
// build that looks exactly like a real OrioleDB one, with no orioledb_sha to
// say otherwise.

// ResolvedRef prefers the remote-tracking branch over a local one.
//
// `git fetch` advances refs/remotes/origin/main and does not touch the local
// branch or the checkout, so reading anything from the working tree uses
// whatever was last checked out by hand -- on one occasion an OrioleDB eleven
// days stale, and every pinned PostgreSQL fork with it.
func ResolvedRef(repo, ref string) string {
	if ref == "" {
		ref = "main"
	}
	if ok(repo, "refs/remotes/origin/"+ref+"^{commit}") {
		return "origin/" + ref
	}
	return ref
}

// PatchsetFor resolves a bare PostgreSQL major to the fork commit OrioleDB
// pins it to.
//
// READ OUT OF THE RESOLVED REF, not off disk, for the reason above. OrioleDB
// refuses to build against any other patchset commit, so this is not a
// convenience: a major on its own is not a buildable ref.
func PatchsetFor(orioleRepo, orioleRef, major string) (string, error) {
	resolved := ResolvedRef(orioleRepo, orioleRef)
	out, err := exec.Command("git", "-C", orioleRepo, "show", resolved+":.pgtags").Output()
	if err != nil {
		return "", fmt.Errorf("cannot read .pgtags from %s: %w", resolved, err)
	}
	var pinned string
	for _, line := range strings.Split(string(out), "\n") {
		k, v, ok := strings.Cut(line, ": ")
		if !ok {
			continue
		}
		if strings.TrimSpace(k) == major {
			pinned = strings.TrimSpace(v) // last wins, as the shell took it
		}
	}
	if pinned == "" {
		return "", fmt.Errorf("no PostgreSQL %s patchset in %s:.pgtags", major, resolved)
	}
	return pinned, nil
}

// IsBareMajor reports whether a ref is just a major version, which only means
// something for the OrioleDB flavour.
func IsBareMajor(ref string) bool {
	if ref == "" {
		return false
	}
	for _, c := range ref {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// OrioleCommit is the extension commit a build was made from, for the record.
//
// Without it a fork-only build and a real OrioleDB build are indistinguishable
// after the fact, which is exactly what the missing extension export would
// have produced.
func OrioleCommit(repo, ref string) string {
	out, err := exec.Command("git", "-C", repo, "rev-parse", "--short",
		ResolvedRef(repo, ref)+"^{commit}").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func ok(repo, rev string) bool {
	return exec.Command("git", "-C", repo, "rev-parse", "--verify", "--quiet", rev).Run() == nil
}

// ExportTree writes one ref's contents into a directory, with no .git.
//
// archive|tar rather than a worktree: what lands is exactly the ref's files,
// which is what gets bind-mounted into the build.
func ExportTree(repo, ref, dst string) error {
	if err := os.RemoveAll(dst); err != nil {
		return err
	}
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return err
	}
	ar := exec.Command("git", "-C", repo, "archive", ref)
	tr := exec.Command("tar", "-x", "-C", dst)
	pipe, err := ar.StdoutPipe()
	if err != nil {
		return err
	}
	tr.Stdin = pipe
	if err := ar.Start(); err != nil {
		return err
	}
	if err := tr.Run(); err != nil {
		return fmt.Errorf("extracting %s: %w", ref, err)
	}
	return ar.Wait()
}

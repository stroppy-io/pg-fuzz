// Package source exports the PostgreSQL tree a build compiles.
//
// git archive, not a checkout: it exports COMMITTED state only, so every crash
// can be tied back to an exact commit. The build patches and litters the tree,
// which is why each workspace gets its own export rather than sharing one.
package source

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Repo is a clone this tool exports from.
type Repo struct {
	Dir string
}

// Fetch refreshes refs.
//
// Unconditionally, not only when a ref fails to resolve. The matrix fuzzes
// branch HEADs as well as tags, and a stale HEAD silently tests yesterday's
// code -- which defeats the point of testing HEADs, namely knowing whether a
// finding is still live upstream and therefore worth reporting.
func (r Repo) Fetch(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "git", "-C", r.Dir,
		"fetch", "--tags", "--prune", "--quiet", "origin")
	var buf bytes.Buffer
	cmd.Stderr = &buf
	if err := cmd.Run(); err != nil {
		// Not fatal: the cached refs may still be what is wanted, and a
		// network blip should not stop a rebuild of a pinned tag.
		return fmt.Errorf("fetch failed, continuing with cached refs: %w", err)
	}
	return nil
}

// Resolve turns a ref into a commit.
func (r Repo) Resolve(ctx context.Context, ref string) (short, full string, err error) {
	full, err = r.revParse(ctx, ref)
	if err != nil {
		// A branch that only exists on the remote.
		full, err = r.revParse(ctx, "origin/"+ref)
		if err != nil {
			return "", "", fmt.Errorf("cannot resolve %q in %s", ref, r.Dir)
		}
	}
	short = full
	if len(short) > 10 {
		short = short[:10]
	}
	return short, full, nil
}

func (r Repo) revParse(ctx context.Context, what string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", "-C", r.Dir, "rev-parse", "--verify", what+"^{commit}")
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// IsMoving reports whether a ref is a branch rather than a tag or a commit.
//
// The distinction matters for reporting: a finding against a moving branch is
// only meaningful against the commit it actually resolved to, which is why the
// export records the full hash.
func (r Repo) IsMoving(ctx context.Context, ref string) bool {
	cmd := exec.CommandContext(ctx, "git", "-C", r.Dir, "rev-parse", "--verify",
		"refs/remotes/"+ref)
	if cmd.Run() == nil {
		return true
	}
	cmd = exec.CommandContext(ctx, "git", "-C", r.Dir, "rev-parse", "--verify",
		"refs/heads/"+ref)
	return cmd.Run() == nil
}

// Export writes the tree at ref into dir, replacing whatever was there.
func (r Repo) Export(ctx context.Context, ref, dir string, stream io.Writer) (short, full string, err error) {
	short, full, err = r.Resolve(ctx, ref)
	if err != nil {
		return "", "", err
	}
	if err := os.RemoveAll(dir); err != nil {
		return "", "", err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", "", err
	}

	archive := exec.CommandContext(ctx, "git", "-C", r.Dir, "archive", full)
	untar := exec.CommandContext(ctx, "tar", "-x", "-C", dir)
	pipe, err := archive.StdoutPipe()
	if err != nil {
		return "", "", err
	}
	untar.Stdin = pipe
	var errb bytes.Buffer
	archive.Stderr, untar.Stderr = &errb, &errb

	if err := untar.Start(); err != nil {
		return "", "", err
	}
	if err := archive.Run(); err != nil {
		return "", "", fmt.Errorf("git archive: %w\n%s", err, errb.String())
	}
	if err := untar.Wait(); err != nil {
		return "", "", fmt.Errorf("tar: %w\n%s", err, errb.String())
	}

	// The FULL hash, third field. OrioleDB's configure derives its patchset
	// version from `git rev-parse HEAD` in the PostgreSQL tree, and an export
	// has no .git -- so build.sh has to be handed it here.
	stamp := fmt.Sprintf("%s %s %s\n", ref, short, full)
	if err := os.WriteFile(filepath.Join(dir, ".pgfuzz-ref"), []byte(stamp), 0o644); err != nil {
		return "", "", err
	}
	return short, full, nil
}

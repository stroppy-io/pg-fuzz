package build

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// Move relocates a finished build into the workspace.
//
// os.Rename alone is not enough, and the case is not exotic. The build lands
// in $PGFUZZ_CACHE/oss-fuzz/build/out and has to reach $PGFUZZ_WS/<ws>/builds,
// and those are separate roots precisely so they can sit on separate
// filesystems -- clones on a fast disk, workspaces on a big one. Rename across
// filesystems returns EXDEV, and the old code reported "keeping build in
// place" and carried on: the workspace then had no builds/ directory at all,
// so coverage, archiving and reown had nothing to find, and on the run that
// caught this the build was left sitting in a tmpfs, holding 1.5G of RAM until
// the next reboot silently deleted it.
//
// So EXDEV falls back to a copy. Everything else is still an error.
func Move(from, to string) error {
	if err := os.MkdirAll(filepath.Dir(to), 0o755); err != nil {
		return err
	}
	if err := os.RemoveAll(to); err != nil {
		return err
	}
	if err := os.Rename(from, to); err == nil {
		return nil
	} else if !errors.Is(err, syscall.EXDEV) {
		return err
	}
	// Copy to a sibling first and rename into place, so an interrupted copy
	// cannot leave a half-built tree looking like a finished one.
	tmp := to + ".partial"
	os.RemoveAll(tmp)
	if err := copyTree(from, tmp); err != nil {
		os.RemoveAll(tmp)
		return err
	}
	if err := os.Rename(tmp, to); err != nil {
		os.RemoveAll(tmp)
		return err
	}
	return os.RemoveAll(from)
}

// copyTree copies a directory, preserving the mode -- which for a build means
// preserving the execute bit on every fuzz target.
func copyTree(from, to string) error {
	return filepath.Walk(from, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(from, p)
		if err != nil {
			return err
		}
		dst := filepath.Join(to, rel)
		switch {
		case fi.IsDir():
			return os.MkdirAll(dst, fi.Mode().Perm())
		case fi.Mode()&os.ModeSymlink != 0:
			target, err := os.Readlink(p)
			if err != nil {
				return err
			}
			return os.Symlink(target, dst)
		case !fi.Mode().IsRegular():
			return nil // devices and sockets have no business in a build
		}
		in, err := os.Open(p)
		if err != nil {
			return err
		}
		defer in.Close()
		out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, fi.Mode().Perm())
		if err != nil {
			return err
		}
		if _, err := io.Copy(out, in); err != nil {
			out.Close()
			return err
		}
		return out.Close()
	})
}

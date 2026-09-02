package incontainer

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
)

// Own implements `_own <dir> <uid> <gid>`: give a tree back to a host user.
//
// This is the container half of corpus.Repair. It replaces
//
//	sh -c "chown -R u:g /corpus && chmod -R u+rwX,go+rX /corpus"
//
// which was the last shell string this tool handed to a container. The walk is
// the same, but errors are per-file and reported: `chown -R` stops on the first
// failure and says nothing about the rest, and a partial repair that reports
// success is exactly how the unreadable-corpus bug hid the first time.
func Own(argv []string) int {
	if len(argv) != 3 {
		fmt.Fprintln(os.Stderr, "usage: _own <dir> <uid> <gid>")
		return 2
	}
	uid, err1 := strconv.Atoi(argv[1])
	gid, err2 := strconv.Atoi(argv[2])
	if err1 != nil || err2 != nil {
		fmt.Fprintln(os.Stderr, "_own: uid and gid must be numeric")
		return 2
	}

	failed, err := Chown(argv[0], uid, gid)
	if err != nil {
		fmt.Fprintf(os.Stderr, "_own: %v\n", err)
		return 1
	}
	if failed > 0 {
		fmt.Fprintf(os.Stderr, "_own: %d entries could not be repaired\n", failed)
		return 1
	}
	return 0
}

// Chown is the walk behind _own, exposed so the fuzzing half can hand back the
// small directories it writes into without a second container.
//
// Errors are per-entry and counted rather than fatal: `chown -R` stops at the
// first failure and says nothing about the rest, and a partial repair that
// reports success is exactly how the unreadable-corpus bug hid the first time.
func Chown(root string, uid, gid int) (failed int, err error) {
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			fmt.Fprintf(os.Stderr, "_own: %v\n", err)
			failed++
			return nil // keep going: one bad entry must not hide the rest
		}
		if err := os.Lchown(p, uid, gid); err != nil {
			fmt.Fprintf(os.Stderr, "_own: chown %s: %v\n", p, err)
			failed++
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return nil // a symlink's mode is not the target's mode
		}
		// u+rwX,go+rX -- X is "execute only where it already applies", which
		// means directories AND files that are already executable. Reading it
		// as "directories" alone is wrong and silently disarms a build: the
		// fuzz targets under /out are exactly the already-executable files,
		// and 0644 makes every one of them unrunnable.
		mode := fs.FileMode(0o644)
		if d.IsDir() {
			mode = 0o755
		} else if info, err := d.Info(); err == nil && info.Mode().Perm()&0o111 != 0 {
			mode = 0o755
		}
		if err := os.Chmod(p, mode); err != nil {
			fmt.Fprintf(os.Stderr, "_own: chmod %s: %v\n", p, err)
			failed++
		}
		return nil
	})
	return failed, err
}

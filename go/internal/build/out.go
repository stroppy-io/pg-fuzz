package build

import (
	"os"
	"path/filepath"
)

// Out is a workspace's OWN build directory.
//
// NOT THE SHARED SYMLINK. `<oss-fuzz>/build/out/<project>` is one path that
// every workspace's build points at in turn, which is why runs and coverage
// resolve `<ws>/builds/<key>` first -- the symlink is shared state another
// workspace's build repoints out from under you.
//
// The archive, the fingerprint and the inventory all joined the shared path
// directly, with the project prefix hardcoded rather than read from the
// workspace's own conf. So a symlink pointing at another workspace's build
// yielded a manifest with the WRONG fuzzer hashes, and a dangling one yielded
// a manifest with no hashes and no BUILD-INFO at all -- silently, where the
// shell's build-sync check failed loudly.
//
// key is the workspace's build key from its conf; project is its project name.
// Either may be empty, and the fallback is the shared path, which is still
// right for a workspace that has never had a per-key build.
func Out(ossFuzz, wsDir, key, project string) string {
	if key != "" {
		if p := filepath.Join(wsDir, "builds", key); isDir(p) {
			return p
		}
	}
	return filepath.Join(ossFuzz, "build", "out", project)
}

// OutDangling reports whether the shared path is a symlink pointing nowhere.
//
// This is the state that produced a Python traceback out of OSS-Fuzz with no
// mention of a symlink, and the state the shell's check-build-sync called a
// FAIL. Reported rather than repaired here: a reader wants to know its answer
// is empty because the build moved, not to have the path quietly fixed.
func OutDangling(ossFuzz, project string) bool {
	p := filepath.Join(ossFuzz, "build", "out", project)
	fi, err := os.Lstat(p)
	if err != nil || fi.Mode()&os.ModeSymlink == 0 {
		return false
	}
	_, err = os.Stat(p)
	return err != nil
}

func isDir(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

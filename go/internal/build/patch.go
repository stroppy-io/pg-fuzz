package build

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// ApplyPatches applies a workspace's patch series to the exported source.
//
// THIS WAS MISSING FROM THE PORT, silently, and in the same shape as the
// plugins were: `patch=` in workspace.conf was read by `inventory` for
// reporting and by nothing else, so a workspace that declared a patch series
// built WITHOUT it and said nothing. An unpatched build that everything
// downstream labels "patched" is worse than a failed one -- it fuzzes
// something that is not what anyone thinks it is, and the results are
// attributed to code that was never compiled in.
//
// Applied on the host, against the export, BEFORE the container runs: the
// export is re-made on every build, so a tree patched by hand is gone the next
// time anything is rebuilt. It also has to precede build.sh's own patches, so
// that add_fuzzers.diff -- generated against master and relying on fuzz factor
// to absorb drift -- sees the tree the fuzzers will actually be compiled into.
//
// The series is applied in ORDER and judged AS A WHOLE. Per-patch exit status
// is deliberately ignored: in a series a later patch commonly repairs what an
// earlier one could not apply, so a non-zero status partway through says
// nothing about the final tree. Leftover .rej files do, and they are the gate.
func ApplyPatches(srcDir string, patches []string, out io.Writer) ([]string, error) {
	if len(patches) == 0 {
		return nil, nil
	}
	for _, p := range patches {
		if _, err := os.Stat(p); err != nil {
			return nil, fmt.Errorf("workspace patch not found: %s", p)
		}
	}

	logPath := filepath.Join(srcDir, ".patch.log")
	lf, err := os.Create(logPath)
	if err != nil {
		return nil, err
	}
	defer lf.Close()

	// Files a patch writes get the current time; anything already in the export
	// is older. Taken before the first patch so the shebang repair below can
	// tell what the series added.
	started := time.Now()

	var applied []string
	for _, p := range patches {
		name := filepath.Base(p)
		if out != nil {
			fmt.Fprintf(out, "    applying %s\n", name)
		}
		cmd := exec.Command("patch", "-p1", "-F3", "-l",
			"--no-backup-if-mismatch", "-d", srcDir, "-i", p)
		cmd.Stdout, cmd.Stderr = lf, lf
		_ = cmd.Run() // judged as a series, below
		applied = append(applied, name)
	}

	// THE REAL GATE. A rejected hunk that nothing repaired leaves a .rej
	// behind, and a half-patched tree compiles fine and then fuzzes something
	// nobody intended -- so fail here rather than discover it from strange
	// results a day later.
	var rejects []string
	filepath.WalkDir(srcDir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(p, ".rej") {
			rejects = append(rejects, p)
		}
		return nil
	})
	if len(rejects) > 0 {
		shown := rejects
		if len(shown) > 20 {
			shown = shown[:20]
		}
		return nil, fmt.Errorf("patch series does not fit this tree: %d hunk(s) unapplied, see %s\n  %s",
			len(rejects), logPath, strings.Join(shown, "\n  "))
	}

	// Restore the executable bit on anything the series added with a shebang.
	//
	// A patch produced by `diff -ruN` carries no file modes at all -- only
	// git-format patches do -- so a script a patch adds arrives
	// non-executable and whatever runs it fails with a bare "Error 126",
	// which says nothing about permissions. Keyed on the shebang rather than
	// the extension: a file that declares an interpreter is meant to be run.
	filepath.WalkDir(srcDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		fi, err := d.Info()
		if err != nil || !fi.ModTime().After(started) || fi.Mode().Perm()&0o111 != 0 {
			return nil
		}
		f, err := os.Open(p)
		if err != nil {
			return nil
		}
		var head [2]byte
		n, _ := f.Read(head[:])
		f.Close()
		if n == 2 && head[0] == '#' && head[1] == '!' {
			os.Chmod(p, fi.Mode().Perm()|0o755)
		}
		return nil
	})

	// .orig copies confuse nothing but bloat the export and show up in
	// otherwise clean diffs.
	filepath.WalkDir(srcDir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(p, ".orig") {
			os.Remove(p)
		}
		return nil
	})

	return applied, nil
}

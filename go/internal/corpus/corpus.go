// Package corpus handles the inputs a campaign accumulates.
//
// THE PERMISSION PROBLEM, WHICH IS NOT COSMETIC
// =============================================
// The postmaster-backed targets run PostgreSQL, which calls umask(077) for the
// life of the process -- so every corpus entry those targets write is mode 600
// and owned by the container's user. A host-side tool then reads about 2% of
// the corpus and reports that as the whole thing.
//
// Repair happens BEFORE a run as well as after. Cleanup that only runs on the
// happy path is missing exactly when something went wrong, and SIGKILL cannot
// be trapped at all -- every campaign stopped mid-slice leaves entries behind.
package corpus

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// Stats is what a corpus directory holds.
type Stats struct {
	Files      int
	Bytes      int64
	Unreadable int
	Foreign    int // not owned by this user
}

// Measure counts a corpus, and counts what it cannot read separately.
//
// Separately on purpose: a tool that silently skips what it cannot open
// reports a corpus of 20,000 as 400 and nothing looks wrong.
func Measure(dir string) Stats {
	var s Stats
	filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		s.Files++
		fi, err := d.Info()
		if err != nil {
			s.Unreadable++
			return nil
		}
		s.Bytes += fi.Size()
		if f, err := os.Open(p); err != nil {
			s.Unreadable++
		} else {
			f.Close()
		}
		// Counted separately from Unreadable, because a root-owned file at
		// mode 0644 reads fine and so hid from every check keyed on reading:
		// 6,949 of them had accumulated while repair reported nothing to do.
		if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Getuid() {
			s.Foreign++
		}
		return nil
	})
	return s
}

// Repair makes a corpus readable again.
//
// Through a container, because the host user cannot chown what it does not
// own. These files are mode 600 and owned by ROOT -- PostgreSQL's umask(077)
// inside the container, written by the postmaster-backed targets -- and
// os.Chmod on one of those fails silently for a non-owner. The first version
// of this reported "repaired 0" while two files stayed unreadable, which is
// the shape of failure this whole package exists to make visible.
//
// docker's root can, and docker is already a dependency.
func Repair(dir string) (fixed int, err error) {
	m := Measure(dir)
	before := m.Unreadable + m.Foreign
	if before == 0 {
		// Free when there is nothing to fix, which is why this can run before
		// every slice as well as after.
		return 0, nil
	}
	self, err := os.Executable()
	if err != nil {
		return 0, err
	}
	if real, err := filepath.EvalSymlinks(self); err == nil {
		self = real
	}
	cmd := exec.Command("docker", "run", "--rm",
		"-v", dir+":/corpus",
		"-v", self+":/pgfuzz:ro",
		"--entrypoint", "/pgfuzz",
		"gcr.io/oss-fuzz-base/base-runner:ubuntu-24-04",
		"_own", "/corpus", strconv.Itoa(os.Getuid()), strconv.Itoa(os.Getgid()))
	if out, err := cmd.CombinedOutput(); err != nil {
		return 0, fmt.Errorf("repair failed: %w\n%s", err, out)
	}
	// Re-measure rather than trust the repair reported success.
	a := Measure(dir)
	return before - (a.Unreadable + a.Foreign), nil
}

// Seed copies inputs from one workspace's corpus into another.
//
// Copies, never moves or links: the source campaign keeps running, and a
// hard link means a later minimisation in one workspace silently changes the
// other's corpus.
// seedDir copies one target's inputs, recursing.
//
// SUBDIRECTORIES ARE STILL INPUTS. The shell copied with `cp -rn`, which
// recurses; this skipped any directory inside a target directory. Nothing
// writes nested corpus entries today, so it was latent -- but a seed that
// silently drops part of a corpus is the failure this file is about, and depth
// is not a reason to skip.
func seedDir(src, dst string) (SeedResult, error) {
	var res SeedResult
	ents, err := os.ReadDir(src)
	if err != nil {
		return res, err
	}
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return res, err
	}
	for _, e := range ents {
		s, d := filepath.Join(src, e.Name()), filepath.Join(dst, e.Name())
		if e.IsDir() {
			sub, err := seedDir(s, d)
			res.Copied += sub.Copied
			res.Present += sub.Present
			res.Failed += sub.Failed
			if res.FirstErr == nil {
				res.FirstErr = sub.FirstErr
			}
			if err != nil && res.FirstErr == nil {
				res.FirstErr = err
			}
			continue
		}
		// libFuzzer names corpus files after the SHA-1 of their content, so a
		// name that already exists is the same input -- skipping is correct
		// and cheap, and re-copying would only rewrite it.
		if _, err := os.Stat(d); err == nil {
			res.Present++
			continue
		}
		if err := copyFile(s, d); err != nil {
			// A FAULT, not a duplicate. Counting it as skipped and printing
			// "already present" is how an unreadable source reported success.
			res.Failed++
			if res.FirstErr == nil {
				res.FirstErr = err
			}
			continue
		}
		res.Copied++
	}
	return res, nil
}

// SeedResult separates what happened, because one counter could not.
//
// "already present" and "could not be copied" were both counted as skipped and
// printed as "N already present", so a half-readable source reported success.
// Present is correct and cheap -- libFuzzer names files after the SHA-1 of
// their content, so a name that exists is the same input. Failed is a fault.
type SeedResult struct {
	Copied  int
	Present int
	Failed  int
	// FirstErr is why the first failure happened, so a caller can say more
	// than a count.
	FirstErr error
}

// Seed copies one workspace's corpus into another.
//
// The int returns are kept for callers that only want the totals; SeedInto
// gives the breakdown.
func Seed(srcRoot, dstRoot string) (copied, skipped int, err error) {
	r, err := SeedInto(srcRoot, dstRoot)
	return r.Copied, r.Present + r.Failed, err
}

// SeedInto is Seed with the failures separated from the duplicates.
func SeedInto(srcRoot, dstRoot string) (SeedResult, error) {
	var res SeedResult
	targets, err := os.ReadDir(srcRoot)
	if err != nil {
		return res, err
	}
	for _, t := range targets {
		if !t.IsDir() {
			continue
		}
		src := filepath.Join(srcRoot, t.Name())
		dst := filepath.Join(dstRoot, t.Name())
		if err := os.MkdirAll(dst, 0o755); err != nil {
			return res, err
		}
		sub, err := seedDir(src, dst)
		res.Copied += sub.Copied
		res.Present += sub.Present
		res.Failed += sub.Failed
		if res.FirstErr == nil {
			res.FirstErr = sub.FirstErr
		}
		if err != nil && res.FirstErr == nil {
			res.FirstErr = err
		}
	}
	return res, nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Chmod(0o644)
}

// Human renders a byte count.
func Human(b int64) string {
	const u = 1024
	if b < u {
		return fmt.Sprintf("%dB", b)
	}
	div, exp := int64(u), 0
	for n := b / u; n >= u; n /= u {
		div *= u
		exp++
	}
	return fmt.Sprintf("%.1f%cB", float64(b)/float64(div), "KMGTPE"[exp])
}

// Artifacts lists the crash, oom, timeout and leak files in a directory.
//
// The four prefixes libFuzzer writes, and nothing else: a corpus input that
// happens to sit beside them is not a finding, and counting it as one inflates
// the number this whole package exists to keep honest.
func Artifacts(dir string) []string {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range ents {
		if e.IsDir() {
			continue
		}
		for _, p := range []string{"crash-", "oom-", "timeout-", "leak-"} {
			if strings.HasPrefix(e.Name(), p) {
				out = append(out, e.Name())
				break
			}
		}
	}
	return out
}

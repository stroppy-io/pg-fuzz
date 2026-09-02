// Package tidy reclaims disk without losing history.
//
// WHY THIS IS A COMMAND AND NOT AN `rm -rf`
// =========================================
// A fuzzing campaign fills a disk in ways that are not obvious, and the largest
// directories are not the ones that are safe to remove. A coverage replay once
// grew one container to ~246 GB and filled a 541 GB disk mid-campaign. The
// reflex is to delete the biggest thing; here the biggest thing is usually the
// evolved corpora, which are the accumulated value of every campaign to date
// and the slowest thing to rebuild.
//
// So this reports first, acts only on request, and separates what it finds:
//
//	COMPRESS   console logs of a sweep or campaign. NEVER deleted. They are
//	           the ONLY record of per-target execution counts, which is what
//	           both the starvation gate and the ratchet read -- deleting them
//	           destroys the evidence behind every floor in the baseline. They
//	           are also almost pure repetition (libFuzzer status lines) and
//	           compress about 12:1, once 20 GB -> 46 MB. The ratchet reads
//	           .log.gz transparently, which went in BEFORE any of this existed:
//	           a tool that silently finds no log reports "no baseline yet", and
//	           that reads as a pass.
//	DOCKER     stopped containers and dangling layers. Regenerated or dead.
//	           Tagged images are deliberately NOT pruned: the locally built
//	           pgfuzz-* images cost hours per workspace to rebuild.
//	CORPORA    evolved corpora. NOT safe, and not offered here at all --
//	           `corpus -minimize` shrinks them reversibly instead.
package tidy

import (
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Options bounds what is considered.
type Options struct {
	Root     string
	MinBytes int64         // ignore logs smaller than this
	MinAge   time.Duration // and logs touched more recently than this
	Apply    bool
	Docker   bool
}

// Candidate is one log worth compressing.
type Candidate struct {
	Path  string
	Bytes int64
	Age   time.Duration
}

// Scan finds the logs, largest first.
//
// It refuses a log that is still being written: compressing the file a running
// campaign is appending to would truncate the run's own record. "Still being
// written" is approximated by mtime, because the alternative -- asking which
// process holds it open -- needs /proc access this may not have.
func Scan(o Options) ([]Candidate, error) {
	if o.MinBytes == 0 {
		o.MinBytes = 10 << 20
	}
	if o.MinAge == 0 {
		o.MinAge = time.Hour
	}
	var out []Candidate
	err := filepath.WalkDir(o.Root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // an unreadable subtree is not a reason to report nothing
		}
		if d.IsDir() {
			// corpus/ holds hundreds of thousands of tiny files and no logs.
			if d.Name() == "corpus" || d.Name() == "corpus-backups" {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".log") {
			return nil
		}
		fi, err := d.Info()
		if err != nil || fi.Size() < o.MinBytes {
			return nil
		}
		age := time.Since(fi.ModTime())
		if age < o.MinAge {
			return nil
		}
		out = append(out, Candidate{p, fi.Size(), age})
		return nil
	})
	// Largest first: the report is read top-down and the first line should be
	// the one that matters.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j].Bytes > out[j-1].Bytes; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out, err
}

// Compress gzips one log and removes the original only after the compressed
// copy is complete and closed. A crash mid-way leaves both, never neither.
func Compress(c Candidate) (saved int64, err error) {
	in, err := os.Open(c.Path)
	if err != nil {
		return 0, err
	}
	defer in.Close()

	tmp := c.Path + ".gz.part"
	f, err := os.Create(tmp)
	if err != nil {
		return 0, err
	}
	zw := gzip.NewWriter(f)
	if _, err := io.Copy(zw, in); err != nil {
		zw.Close()
		f.Close()
		os.Remove(tmp)
		return 0, err
	}
	if err := zw.Close(); err != nil {
		f.Close()
		os.Remove(tmp)
		return 0, err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return 0, err
	}
	if err := os.Rename(tmp, c.Path+".gz"); err != nil {
		os.Remove(tmp)
		return 0, err
	}
	st, err := os.Stat(c.Path + ".gz")
	if err != nil {
		return 0, err
	}
	if err := os.Remove(c.Path); err != nil {
		return 0, err
	}
	return c.Bytes - st.Size(), nil
}

// DockerReclaim removes stopped containers and dangling layers, and reports
// how many tagged pgfuzz images it deliberately left alone.
func DockerReclaim(ctx context.Context, apply bool) (stopped, dangling, kept int, err error) {
	count := func(args ...string) int {
		out, err := exec.CommandContext(ctx, "docker", args...).Output()
		if err != nil {
			return 0
		}
		return len(strings.Fields(string(out)))
	}
	stopped = count("ps", "-aq", "-f", "status=exited", "-f", "status=created")
	dangling = count("images", "-qf", "dangling=true")

	out, _ := exec.CommandContext(ctx, "docker", "images", "--format", "{{.Repository}}").Output()
	for _, l := range strings.Split(string(out), "\n") {
		if strings.Contains(l, "pgfuzz-") {
			kept++
		}
	}
	if !apply {
		return stopped, dangling, kept, nil
	}
	if stopped > 0 {
		if e := exec.CommandContext(ctx, "docker", "container", "prune", "-f").Run(); e != nil {
			err = fmt.Errorf("container prune: %w", e)
		}
	}
	if dangling > 0 {
		if e := exec.CommandContext(ctx, "docker", "image", "prune", "-f").Run(); e != nil && err == nil {
			err = fmt.Errorf("image prune: %w", e)
		}
	}
	return stopped, dangling, kept, err
}

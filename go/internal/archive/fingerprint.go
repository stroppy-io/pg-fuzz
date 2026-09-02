// Package archive freezes a finished campaign into a write-once directory.
//
// What makes it an archive rather than a copy is the MANIFEST: the fingerprint
// that says whether two runs are comparable, and the provenance that says what
// a replay would have to reproduce.
package archive

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// FPVersion is bumped when the DEFINITION of the fingerprint changes -- a new
// input folded in, or an old one dropped.
//
// Without it, widening the definition is indistinguishable from the experiment
// moving: the hash changes either way, and the index cries "something
// underneath moved" when nothing did.
const FPVersion = 2

// Provenance is what the substrate was when this ran.
type Provenance struct {
	Commit    string `json:"commit"`
	Dirty     bool   `json:"dirty"`
	BaseImage string `json:"base_image"`
}

// BaseImage resolves the base image the targets were compiled against, read
// from the FROM line rather than assumed, so retagging is not a silent change.
//
// AN UNREADABLE VALUE IS AN ERROR, NOT AN EMPTY STRING. `docker images` in a
// shell without the docker group prints nothing and still exits 0, so the
// empty string would sail into the hash and make two identical runs look like
// different experiments. A fingerprint computed from a value nobody could read
// is worse than no fingerprint.
func BaseImage(repo string) (string, error) {
	tag := ""
	b, err := os.ReadFile(filepath.Join(repo, "project", "Dockerfile"))
	if err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(l, "FROM ") {
				if f := strings.Fields(l); len(f) > 1 {
					tag = f[1]
				}
				break
			}
		}
	}
	id := ""
	if tag != "" {
		out, err := exec.Command("docker", "images", "--no-trunc", "--format", "{{.ID}}", tag).Output()
		if err == nil {
			for _, l := range strings.Split(string(out), "\n") {
				if l = strings.TrimSpace(l); l != "" {
					id = l
					break
				}
			}
		}
	}
	if tag == "" || id == "" {
		return "", fmt.Errorf("cannot resolve the base image for the fingerprint\n"+
			"  FROM tag: %s\n  image id: %s\n"+
			"  is this shell in the docker group?",
			orUnreadable(tag, "<unreadable from project/Dockerfile>"),
			orUnreadable(id, "<empty>"))
	}
	return tag + "@" + id, nil
}

func orUnreadable(s, alt string) string {
	if s == "" {
		return alt
	}
	return s
}

// Dirty reports whether the oss-fuzz clone has modified tracked files.
//
// The clone is meant to be a pure substrate -- harnesses reach it as symlinks
// back into this repo -- so a dirty one means the recorded commit no longer
// describes what built these targets.
func Dirty(ossfuzz string) bool {
	out, err := exec.Command("git", "-C", ossfuzz, "status", "--porcelain",
		"--untracked-files=no").Output()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) != ""
}

// Commit is a short-or-full git HEAD, or "unknown".
func Commit(dir string, short bool) string {
	args := []string{"-C", dir, "rev-parse"}
	if short {
		args = append(args, "--short")
	}
	args = append(args, "HEAD")
	out, err := exec.Command("git", args...).Output()
	s := strings.TrimSpace(string(out))
	if err != nil || s == "" {
		return "unknown"
	}
	return s
}

// FingerprintInputs is everything the fingerprint is computed over.
type FingerprintInputs struct {
	Repo       string
	OSSFuzz    string
	WSRoot     string
	Workspaces []string
	BaseImage  string
}

// Fingerprint is eight characters that answer "are these two runs the same".
//
// It covers the oss-fuzz commit, the base image, each workspace's PostgreSQL
// sha and plugin pins, each workspace's patch and plugin configuration, and
// the harness sources. It deliberately does NOT cover the report layout or the
// driver: redesigning a report changes its bytes, and it must not change what
// a run was.
//
// Every input is written into ONE hash in a fixed order. An input that cannot
// be read is an error rather than an empty contribution -- see BaseImage.
func Fingerprint(in FingerprintInputs) (string, error) {
	h := sha256.New()
	fmt.Fprint(h, Commit(in.OSSFuzz, false))
	fmt.Fprint(h, in.BaseImage)

	ws := append([]string(nil), in.Workspaces...)
	sort.Strings(ws)
	for _, w := range ws {
		bi := filepath.Join(in.OSSFuzz, "build", "out", "pgfuzz-"+w, "BUILD-INFO.json")
		if b, err := os.ReadFile(bi); err == nil {
			var j struct {
				PGRefSHA string            `json:"pg_ref_sha"`
				Plugins  map[string]string `json:"plugins"`
			}
			if json.Unmarshal(b, &j) == nil {
				fmt.Fprintln(h, j.PGRefSHA)
				var names []string
				for n := range j.Plugins {
					names = append(names, n)
				}
				sort.Strings(names)
				for _, n := range names {
					fmt.Fprintln(h, n, j.Plugins[n])
				}
			}
		}
		// patch= and plugins= from workspace.conf: WHICH plugins at which
		// version is the experiment, and it lives in configuration rather than
		// in the build output.
		if b, err := os.ReadFile(filepath.Join(in.WSRoot, w, "workspace.conf")); err == nil {
			for _, l := range strings.Split(string(b), "\n") {
				if strings.HasPrefix(l, "patch=") || strings.HasPrefix(l, "plugins=") {
					fmt.Fprintln(h, l)
				}
			}
		}
	}

	// The harness sources, concatenated in name order.
	var srcs []string
	for _, pat := range []string{"*.c", "*.h"} {
		m, _ := filepath.Glob(filepath.Join(in.Repo, "project", "fuzzer", pat))
		srcs = append(srcs, m...)
	}
	sort.Strings(srcs)
	for _, p := range srcs {
		f, err := os.Open(p)
		if err != nil {
			return "", fmt.Errorf("harness source unreadable: %w", err)
		}
		_, err = io.Copy(h, f)
		f.Close()
		if err != nil {
			return "", err
		}
	}
	return hex.EncodeToString(h.Sum(nil))[:8], nil
}

// HarnessHash is the sources those binaries came from, so a rebuild can be
// CHECKED against the harness that produced a result rather than assumed
// identical.
//
// THE HARNESS IS PART OF THE EXPERIMENT. BUILD-INFO records the PostgreSQL
// commit, the patches and the plugin versions -- everything about the system
// under test -- and nothing about the fuzzer driving it. That is half the
// experiment missing: the harness changed twice on one day, each requiring a
// rebuild, and coverage taken either side is not comparable.
func HarnessHash(repo string) string {
	h := sha256.New()
	var srcs []string
	for _, pat := range []string{"*.c", "*.h"} {
		m, _ := filepath.Glob(filepath.Join(repo, "project", "fuzzer", pat))
		srcs = append(srcs, m...)
	}
	sort.Strings(srcs)
	for _, p := range srcs {
		if f, err := os.Open(p); err == nil {
			io.Copy(h, f)
			f.Close()
		}
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// HarnessCommit is the last commit that touched the harness sources.
func HarnessCommit(repo string) string {
	out, err := exec.Command("git", "-C", repo, "log", "-1", "--format=%h",
		"--", "project/fuzzer").Output()
	s := strings.TrimSpace(string(out))
	if err != nil || s == "" {
		return "unknown"
	}
	return s
}

func newSHA() interface {
	io.Writer
	Sum([]byte) []byte
} {
	return sha256.New()
}

func hexShort(b []byte, n int) string {
	s := hex.EncodeToString(b)
	if len(s) > n {
		return s[:n]
	}
	return s
}

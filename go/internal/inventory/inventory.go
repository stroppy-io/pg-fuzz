// Package inventory lists every component that goes into a run, and its hash.
//
// WHY
// ===
// The fingerprint is eight characters. It answers "are these two runs the
// same" and nothing else -- when it changes it does not say WHAT changed, and
// when a finding has to be reproduced two years from now, "0cf58f70" is not a
// build recipe. This is the expansion: every input, layer by layer, with the
// hash that identifies it.
//
// Deliberately a SUPERSET of the fingerprint. Some components here are
// recorded but not hashed into it -- the build recipe, the support files --
// because they shape the build without defining the experiment. Where that is
// true it is marked, so the difference is visible rather than implied.
//
// A component whose hash cannot be read is reported as UNREADABLE and counted.
// It is never silently skipped and never given a placeholder: a component list
// with a quiet hole in it is worse than one that admits the hole, because the
// first looks complete.
package inventory

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"

	"path/filepath"
	"pgfuzz/internal/archive"
	"sort"
	"strings"
	"time"
)

// Unreadable is what a component gets instead of a guess.
const Unreadable = "UNREADABLE"

// Component is one input to a run.
type Component struct {
	Layer         string `json:"layer"`
	Name          string `json:"name"`
	Kind          string `json:"kind"`
	Hash          string `json:"hash"`
	Detail        string `json:"detail"`
	InFingerprint bool   `json:"in_fingerprint"`
}

// Report is the whole inventory.
type Report struct {
	Components []Component `json:"components"`
	Unreadable int         `json:"unreadable"`
	Workspaces []string    `json:"workspaces"`
	Generated  string      `json:"generated"`
}

// Roots is what the inventory needs to look at.
type Roots struct {
	Repo    string   // this repository
	OSSFuzz string   // the oss-fuzz clone that builds
	WSRoot  string   // where workspaces live
	Targets []string // workspace names
}

// Collect walks the layers in build order.
func Collect(r Roots) Report {
	var cs []Component
	add := func(layer, name, kind, hash, detail string, inFP bool) {
		cs = append(cs, Component{layer, name, kind, hash, detail, inFP})
	}

	// ---- 1. the build substrate -----------------------------------------
	add("substrate", "oss-fuzz", "git commit", gitHead(r.OSSFuzz, false),
		"build driver, base image definitions", true)

	tag := archive.DockerfileFrom(filepath.Join(r.Repo, "project", "Dockerfile"))
	name := tag
	if name == "" {
		name = "base image"
	}
	add("substrate", name, "docker image", dockerImageID(tag),
		"libFuzzer is linked statically from here", true)

	// The clang revision, READ FROM THE PINNED SCRIPT rather than assumed.
	add("substrate", "llvm-project (clang + libFuzzer)", "git commit",
		clangRevision(r.OSSFuzz),
		"implied by the oss-fuzz commit, not hashed separately", false)

	// ---- 2. the driver --------------------------------------------------
	add("driver", "pg-fuzz", "git commit", gitHead(r.Repo, true),
		"this repository", true)

	// ---- 3. harness ------------------------------------------------------
	var srcs []string
	for _, pat := range []string{"*.c", "*.h"} {
		m, _ := filepath.Glob(filepath.Join(r.Repo, "project", "fuzzer", pat))
		srcs = append(srcs, m...)
	}
	sort.Strings(srcs)
	for _, p := range srcs {
		add("harness", filepath.Base(p), "sha256", ShaFile(p), "fuzzer source", true)
	}
	for _, n := range []string{"build.sh", "Dockerfile", "plugins.tsv",
		"add_fuzzers.diff", "main.diff", "guc_file_nul.diff"} {
		add("harness support", n, "sha256",
			ShaFile(filepath.Join(r.Repo, "project", n)),
			"build recipe / patch", false)
	}

	// ---- 4. per workspace: SUT, patches, plugins, binaries ---------------
	for _, ws := range r.Targets {
		c := readConf(filepath.Join(r.WSRoot, ws, "workspace.conf"))
		bi := readBuildInfo(filepath.Join(r.OSSFuzz, "build", "out", "pgfuzz-"+ws, "BUILD-INFO.json"))

		add(ws, "PostgreSQL "+or(c["ref"], "?"), "git commit",
			or(bi.PGRefSHA, Unreadable),
			fmt.Sprintf("%s, %s", or(bi.Sanitizer, "?"), or(bi.ServerTree, "?")), true)

		for _, pf := range strings.Fields(c["patch"]) {
			add(ws, filepath.Base(pf), "sha256", ShaFile(pf), "vendor patch", true)
		}

		var names []string
		for n := range bi.Plugins {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			ref := bi.Plugins[n]
			// "local:<sha>" means a PATCHED TREE, not the released plugin.
			// That distinction decides whether a finding can be reported
			// upstream, so it is carried here rather than flattened into a
			// bare sha.
			detail := "registry pin"
			if strings.HasPrefix(ref, "local:") {
				detail = "PATCHED LOCAL TREE -- not the released plugin"
			}
			add(ws, n, "git commit", strings.TrimPrefix(ref, "local:"), detail, true)
		}

		for _, ext := range strings.Fields(c["extensions"]) {
			add(ws, ext, "n/a", "shipped by patch",
				"created from the vendor patch / contrib; no independent hash", false)
		}

		outdir := filepath.Join(r.OSSFuzz, "build", "out", "pgfuzz-"+ws)
		bins, _ := filepath.Glob(filepath.Join(outdir, "*_fuzzer"))
		sort.Strings(bins)
		n := 0
		for _, p := range bins {
			if st, err := os.Stat(p); err != nil || st.IsDir() {
				continue
			}
			add(ws, filepath.Base(p), "sha256", ShaFile(p),
				"built target; libFuzzer linked in", true)
			n++
		}
		if n == 0 {
			add(ws, "fuzzer binaries", "sha256", Unreadable,
				"no built targets found under "+outdir, true)
		}
	}

	rep := Report{Components: cs, Generated: time.Now().UTC().Format(time.RFC3339)}
	for _, c := range cs {
		if c.Hash == Unreadable {
			rep.Unreadable++
		}
	}
	return rep
}

// ShaFile is the sha256 of one file, truncated for display. UNREADABLE, never
// a guess.
func ShaFile(p string) string {
	f, err := os.Open(p)
	if err != nil {
		return Unreadable
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return Unreadable
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

func gitHead(dir string, short bool) string {
	args := []string{"-C", dir, "rev-parse"}
	if short {
		args = append(args, "--short")
	}
	args = append(args, "HEAD")
	out, err := exec.Command("git", args...).Output()
	s := strings.TrimSpace(string(out))
	if err != nil || s == "" {
		return Unreadable
	}
	return strings.Fields(s)[0]
}

func dockerImageID(tag string) string {
	if tag == "" {
		return Unreadable
	}
	out, err := exec.Command("docker", "images", "--no-trunc", "--format", "{{.ID}}", tag).Output()
	if err != nil {
		return Unreadable
	}
	for _, l := range strings.Split(string(out), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			return l
		}
	}
	return Unreadable
}

func clangRevision(ossfuzz string) string {
	p := filepath.Join(ossfuzz, "infra/base-images/base-clang/checkout_build_install_llvm.sh")
	b, err := os.ReadFile(p)
	if err != nil {
		return Unreadable
	}
	for _, l := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(l, "OUR_CLANG_REVISION=") {
			return strings.TrimSpace(strings.SplitN(l, "=", 2)[1])
		}
	}
	return Unreadable
}

// readConf parses workspace.conf. LAST assignment wins, matching how the shell
// sourced it.
func readConf(path string) map[string]string {
	out := map[string]string{}
	b, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	for _, l := range strings.Split(string(b), "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") || !strings.Contains(l, "=") {
			continue
		}
		k, v, _ := strings.Cut(l, "=")
		out[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return out
}

// BuildInfo is archive's model of BUILD-INFO.json. There is one, deliberately:
// this package had its own, and a second model of the same file written from
// memory is how a provenance column came to print the wrong field.
type BuildInfo = archive.BuildInfo

func readBuildInfo(path string) BuildInfo { return archive.ReadBuildInfo(path) }

func or(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

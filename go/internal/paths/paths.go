// Package paths holds the four roots. It is the Go face of scripts/paths.sh
// and scripts/pgfuzz_paths.py, and deliberately the same names and the same
// precedence, because the whole point of having them is that "where do
// workspaces live" has one answer.
//
// Every root is overridable from the environment; the defaults are relative to
// the user's home, so a second user on the same machine gets a working tree
// with no configuration at all. Until 2026-09-02 the answer was 131 string
// literals under /home/dead, which is why moving this campaign to bare metal
// required the layout to be byte-identical.
package paths

import (
	"fmt"
	"os"
	"path/filepath"
)

// Roots resolved once, at startup.
type Roots struct {
	Home  string // this repository -- tooling, harnesses, patches
	WS    string // workspaces, corpora, artifacts, campaigns, FINDINGS
	Cache string // the postgres/orioledb/oss-fuzz clones; derived state
	Src   string // patch files and locally-patched plugin trees
}

// OSSFuzz is the oss-fuzz clone this tooling drives.
func (r Roots) OSSFuzz() string { return filepath.Join(r.Cache, "oss-fuzz") }

// Out is where a project's built fuzzers land.
func (r Roots) Out(project string) string {
	return filepath.Join(r.OSSFuzz(), "build", "out", project)
}

// Campaigns is where campaigns publish themselves.
func (r Roots) Campaigns() string { return filepath.Join(r.WS, "campaigns") }

// Workspace is one workspace directory.
func (r Roots) Workspace(name string) string { return filepath.Join(r.WS, name) }

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// Resolve reads the environment once.
//
// PGFUZZ_HOME defaults by the executable's own location rather than by $HOME:
// a checkout somewhere else should find its own harnesses and patches, not a
// stranger's. The other three are data and follow $HOME.
func Resolve() Roots {
	home, _ := os.UserHomeDir()

	// FINDING THE CHECKOUT, IF THERE IS ONE.
	//
	// This used to be "three directories up from the executable", which is
	// right for <repo>/go/bin/pgfuzz and wrong for everything else. A binary
	// installed at /usr/local/bin/pgfuzz resolved Home to "/", and then the
	// ratchet read /scripts/ratchet-baseline.json, found nothing, and printed
	// an empty baseline while exiting 0 -- the exact silent-success shape this
	// tool exists to avoid, landing on the one person it was rewritten for:
	// somebody who is not us, running the shipped binary.
	//
	// So a candidate is only accepted if it LOOKS like the checkout. When
	// none does, Home is empty and any command that needs it says where it
	// looked instead of quietly reading nothing.
	self := ""
	if exe, err := os.Executable(); err == nil {
		if real, err := filepath.EvalSymlinks(exe); err == nil {
			exe = real
		}
		self = findCheckout(filepath.Dir(exe))
	}
	if self == "" {
		if wd, err := os.Getwd(); err == nil {
			self = findCheckout(wd)
		}
	}

	return Roots{
		Home:  env("PGFUZZ_HOME", self),
		WS:    env("PGFUZZ_WS", env("PGFUZZ_WS_ROOT", filepath.Join(home, "pgfuzz"))),
		Cache: env("PGFUZZ_CACHE", filepath.Join(home, ".cache", "pgfuzz")),
		Src:   env("PGFUZZ_SRC", filepath.Join(home, "Projects", "sources")),
	}
}

// checkoutMarkers are files that only the pg-fuzz checkout has.
//
// project/build.sh is OSS-Fuzz's contract and go/go.mod is the module root;
// either alone is enough, and requiring both would break a checkout that ships
// one without the other.
var checkoutMarkers = []string{"project/build.sh", "go/go.mod"}

// findCheckout walks up from dir looking for the repository, and returns ""
// rather than a guess.
func findCheckout(dir string) string {
	for i := 0; i < 8 && dir != "" && dir != "/"; i++ {
		for _, m := range checkoutMarkers {
			if _, err := os.Stat(filepath.Join(dir, m)); err == nil {
				return dir
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return ""
}

// NeedHome returns the checkout, or an error naming where it looked.
//
// Called by every command that reads something from the repository -- the
// ratchet baseline, the acknowledgement list, the harness sources. A missing
// checkout must be a refusal, not an empty result.
func (r Roots) NeedHome() (string, error) {
	if r.Home != "" {
		return r.Home, nil
	}
	return "", fmt.Errorf("cannot find the pg-fuzz checkout.\n" +
		"  Looked upward from this binary and from the working directory for\n" +
		"  project/build.sh or go/go.mod. Set PGFUZZ_HOME to the checkout,\n" +
		"  or run this from inside it.")
}

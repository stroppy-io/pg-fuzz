package campaign

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"syscall"
	"time"
)

// A CAMPAIGN IS SELF-CONTAINED.
//
// campaigns/<slug>/ holds everything the campaign ran on and produced: the
// builds, the corpora they fuzzed, the artifacts they found, the logs, the
// series, and a manifest naming what went into each build. The directory can be
// moved to another machine and coverage rerun against the same binaries and the
// same corpus that produced the original numbers.
//
// The alternative -- reading a workspace's builds/ and corpus/ -- has two
// specific failures:
//
//   - A workspace build is overwritten by the next build of that workspace,
//     after which the campaign's results describe binaries that no longer
//     exist. Coverage measured against a different build than the one that
//     fuzzed is not hypothetical here: a coverage build once spent two days
//     measuring stock orafce while the fuzzing builds ran the patched one, and
//     nothing said so, because both were called "orafce".
//   - A workspace corpus is shared, mutable state. `corpus -minimize` or
//     `-autocap` run against the workspace mid-campaign silently changes what
//     the campaign is fuzzing, and the campaign's own new inputs leak back into
//     the workspace. Neither is visible in the result.
//
// LAYOUT. Per workspace, because a campaign has several and their targets have
// the same names -- a flat corpus/<target> would merge pg16's corpus with
// pg19's and neither would ever be separable again:
//
//	campaigns/<slug>/
//	  MANIFEST.json          what each build was: ref, resolved sha, plugins
//	  series.jsonl           append-only, one row per slice
//	  live/campaign.json     the driver's PID, written before the build phase
//	  ws/<name>/build/       the binaries that did the fuzzing
//	  ws/<name>/build.log    what that build printed
//	  ws/<name>/corpus/<target>/
//	  ws/<name>/artifacts/<target>/
//	  ws/<name>/lineage/
//	  ws/<name>/runtmp/      overlay scratch, not evidence

// WSDir is one workspace's directory inside a campaign.
func WSDir(slugDir, ws string) string { return filepath.Join(slugDir, "ws", ws) }

// BuildDir is where one workspace's build lives inside the campaign.
func BuildDir(slugDir, ws string) string { return filepath.Join(WSDir(slugDir, ws), "build") }

// BuildLog is the log for one workspace's build.
//
// One log per workspace rather than a shared one: a shared log cannot say which
// build is running now, which is exactly what a dashboard needs.
func BuildLog(slugDir, ws string) string { return filepath.Join(WSDir(slugDir, ws), "build.log") }

// CorpusDir is the campaign's own corpus for one workspace.
func CorpusDir(slugDir, ws string) string { return filepath.Join(WSDir(slugDir, ws), "corpus") }

// SeedCorpus gives the campaign its own copy of a workspace's corpus.
//
// HARD LINKS, not a copy and not a symlink.
//
// Not a copy because corpora reach millions of files and several gigabytes, and
// a campaign would pay that for every workspace it names.
//
// Not a symlink because a symlink is not a copy at all -- it is the workspace's
// directory under another name, so the two would share one mutable thing. The
// campaign's new inputs would land in the workspace and a minimize run against
// the workspace would delete inputs out from under a running campaign.
//
// Hard links are the thing that is actually wanted: same bytes, no second copy,
// but an independent directory entry. Corpus files are content-addressed and
// never rewritten in place, so sharing the bytes is safe; deleting one side's
// entry leaves the other's intact. `pgfuzz clone` is what turns this into a
// standalone copy when the slug is moved off this filesystem.
//
// Falls back to copying per file, since the roots may be on different disks.
func SeedCorpus(dst, src string) (linked, copied int, err error) {
	var firstLinkErr error
	ents, err := os.ReadDir(src)
	if err != nil {
		// No corpus yet is not an error: a fresh workspace has none, and the
		// campaign is about to grow one.
		if os.IsNotExist(err) {
			return 0, 0, nil
		}
		return 0, 0, err
	}
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		from := filepath.Join(src, e.Name())
		to := filepath.Join(dst, e.Name())
		if err := os.MkdirAll(to, 0o755); err != nil {
			return linked, copied, err
		}
		files, err := os.ReadDir(from)
		if err != nil {
			continue
		}
		for _, f := range files {
			if f.IsDir() {
				continue
			}
			fp, tp := filepath.Join(from, f.Name()), filepath.Join(to, f.Name())
			if _, err := os.Lstat(tp); err == nil {
				continue // already seeded
			}
			if lerr := os.Link(fp, tp); lerr == nil {
				linked++
				continue
			} else if firstLinkErr == nil {
				firstLinkErr = lerr
			}
			if copyFile(fp, tp) == nil {
				copied++
			}
		}
	}
	// A fallback to copying is not a failure, but it is never what was wanted
	// and the reason is never obvious -- fs.protected_hardlinks forbids
	// linking to a file you do not own, which is what a root-owned corpus
	// produces. Reported once rather than per file.
	if firstLinkErr != nil && copied > 0 {
		fmt.Fprintf(os.Stderr,
			"    note: could not hard-link, copied %d inputs instead: %v\n",
			copied, firstLinkErr)
	}
	return linked, copied, nil
}

func copyFile(from, to string) error {
	in, err := os.Open(from)
	if err != nil {
		return err
	}
	defer in.Close()
	fi, err := in.Stat()
	if err != nil {
		return err
	}
	out, err := os.OpenFile(to, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, fi.Mode().Perm())
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// ManifestEntry is what the campaign records about one workspace's build.
//
// The RESOLVED SHA, not just the ref: a finding against origin/master means
// nothing in a report without the commit it was, and a moving branch is not
// provenance. Plugins likewise carry the sha they were built from, which for a
// local tree is local:<sha>[+dirty] rather than a bare "local".
type ManifestEntry struct {
	Workspace string `json:"workspace"`
	Ref       string `json:"ref"`
	SHA       string `json:"sha"`
	// OrioleDBSHA is the storage engine's commit, when there is one. For an
	// OrioleDB workspace it is the commit that matters: the PostgreSQL sha
	// says which base the engine was built against, not which engine.
	OrioleDBSHA  string   `json:"orioledb_sha,omitempty"`
	Sanitizer    string   `json:"sanitizer"`
	Engine       string   `json:"engine"`
	Key          string   `json:"key"`
	Targets      []string `json:"targets"`
	Plugins      []string `json:"plugins,omitempty"`
	PluginsFail  []string `json:"plugins_failed,omitempty"`
	Patches      []string `json:"patches,omitempty"`
	SeededInputs int      `json:"seeded_inputs"`
	BuildOK      bool     `json:"build_ok"`
	Note         string   `json:"note,omitempty"`
}

// Manifest is what a campaign says about itself.
type Manifest struct {
	Slug    string    `json:"slug"`
	Started time.Time `json:"started"`

	// SEALED is the difference between a run you can report and a run you can
	// only have done.
	//
	// A local run SHARES the workspace corpus, and that is the right default:
	// the corpus is the accumulated value of every campaign before it, and a
	// run that contributes back is worth more than one that starts cold.
	//
	// A sealed run gets its own corpus, hard-linked at the moment it started.
	// Nothing outside can change it -- no minimize, no autocap, no other
	// campaign -- and it travels with the slug. That is what makes the numbers
	// re-measurable by somebody who was not here.
	//
	// Recorded because an unsealed campaign's coverage CANNOT be reproduced
	// from its slug, and a manifest that did not say so would be claiming a
	// portability the directory does not have.
	Sealed bool `json:"sealed"`

	OSSFuzz   string          `json:"oss_fuzz_commit"`
	BaseImage string          `json:"base_image"`
	Hours     float64         `json:"hours"`
	PerTarget int             `json:"per_target_seconds"`
	Jobs      int             `json:"jobs"`
	Entries   []ManifestEntry `json:"entries"`
}

// WriteManifest records the campaign, sorted so two runs produce comparable
// files rather than files that differ by map order.
func WriteManifest(slugDir string, m Manifest) error {
	sort.Slice(m.Entries, func(i, j int) bool {
		return m.Entries[i].Workspace < m.Entries[j].Workspace
	})
	if err := os.MkdirAll(slugDir, 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(slugDir, "MANIFEST.json"), append(b, '\n'), 0o644)
}

// ReadManifest reads a campaign's manifest, wherever the directory now sits.
func ReadManifest(slugDir string) (Manifest, error) {
	var m Manifest
	b, err := os.ReadFile(filepath.Join(slugDir, "MANIFEST.json"))
	if err != nil {
		return m, err
	}
	return m, json.Unmarshal(b, &m)
}

// Building lists the workspaces whose build log was written to recently.
//
// From the LOG's mtime rather than from a process: a build is mostly `docker
// build` and `make`, whose command lines say nothing about which workspace they
// belong to, while the log is written by the build itself and names its own
// directory. The freshness window is what stops a finished -- or abandoned --
// build from showing as live forever, and it is why a stale log carried across
// a migration does not read as work in progress.
func Building(slugDir string, within time.Duration) []string {
	hits, _ := filepath.Glob(filepath.Join(slugDir, "ws", "*", "build.log"))
	var out []string
	for _, p := range hits {
		fi, err := os.Stat(p)
		if err != nil || time.Since(fi.ModTime()) > within {
			continue
		}
		ws := filepath.Base(filepath.Dir(p))
		// A FINISHED build is not a running one. Freshness alone kept a
		// workspace marked "building" for the whole window after it had
		// finished -- so three built workspaces sat there spinning while the
		// fourth was the only one actually compiling.
		if HasBuild(slugDir, ws) {
			continue
		}
		out = append(out, ws)
	}
	sort.Strings(out)
	return out
}

// HasBuild says whether the campaign has usable binaries for a workspace.
//
// Asked of the DIRECTORY, not of the manifest: the manifest is written once,
// after every build has been attempted, so during the build phase it does not
// exist yet and cannot answer which workspaces are already done.
func HasBuild(slugDir, ws string) bool {
	hits, _ := filepath.Glob(filepath.Join(BuildDir(slugDir, ws), "*_fuzzer"))
	return len(hits) > 0
}

// BuildFreshness is whether a build belongs to THIS run.
//
// THREE STATES, NOT TWO. The Python distinguished built-this-campaign from a
// build left over from a previous run -- drawn `~` and excluded from the
// header's built count -- from never built. HasBuild is a glob with no
// timestamp test, so re-running a slug counted last week's binaries as this
// run's build and the `~` disappeared from the legend with it.
//
// since is when the campaign started; a build older than that was not made by
// it.
type BuildFreshness int

const (
	NoBuild BuildFreshness = iota
	StaleBuild
	FreshBuild
)

// Freshness classifies a workspace's build against a campaign's start time.
//
// A zero `since` means "cannot tell", and everything built reads as fresh --
// which is the old behaviour, and right when there is no start time to compare
// against rather than a reason to claim staleness.
func Freshness(slugDir, ws string, since time.Time) BuildFreshness {
	hits, _ := filepath.Glob(filepath.Join(BuildDir(slugDir, ws), "*_fuzzer"))
	if len(hits) == 0 {
		return NoBuild
	}
	if since.IsZero() {
		return FreshBuild
	}
	for _, h := range hits {
		if fi, err := os.Stat(h); err == nil && !fi.ModTime().Before(since) {
			return FreshBuild
		}
	}
	return StaleBuild
}

// LiveDriver reports the pid of a campaign still running in this slug, or 0.
//
// BY THE PID, not by the marker file. A marker outlives kill -9, so trusting
// it reports a dead campaign as running forever -- and trusting its ABSENCE
// is worse, since the marker is written before the build phase and a reader
// that only checks for the file would call a building campaign idle.
func LiveDriver(slugDir string) int {
	b, err := os.ReadFile(filepath.Join(slugDir, "live", "campaign.json"))
	if err != nil {
		return 0
	}
	var st State
	if json.Unmarshal(b, &st) != nil || st.PID <= 0 {
		return 0
	}
	if syscall.Kill(st.PID, 0) != nil {
		return 0
	}
	return st.PID
}

// AnyLiveCampaign returns the slug of any campaign still running under root.
//
// A REPORT MUST NOT BE BUILT OVER A MOVING TARGET. The old bundle warned and
// wrote the fact into its manifest; the archive refused outright, because an
// archive of a campaign that is still adding to itself is not an archive of
// anything. Coverage is the sharpest case: measuring it against a corpus that
// grew twelve hours ago, or is growing right now, produces a number that
// belongs to no run.
func AnyLiveCampaign(root string) (slug string, pid int) {
	ents, err := os.ReadDir(root)
	if err != nil {
		return "", 0
	}
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		if p := LiveDriver(filepath.Join(root, e.Name())); p > 0 {
			return e.Name(), p
		}
	}
	return "", 0
}

// Provenance fills the parts of a manifest entry that must describe the build
// THIS campaign performed, rather than whatever the workspace last recorded.
//
// WHY THIS EXISTS. The entry used to take its sha from workspace.conf, which
// is written by a build -- any build, at any time in the past. A workspace
// built during an earlier campaign and merely REUSED by this one therefore
// carried the earlier commit into a sealed manifest, and the verification
// campaign of 2026-09-03 caught it: gt-pg17 was recorded against 61636c17b3
// while both workspaces had in fact compiled 4639b6cfe3. A sealed slug is the
// document that makes a run re-measurable by somebody who was not here; a
// commit in it that was never built is worse than no commit at all, because it
// looks like provenance.
//
// BUILD-INFO.json is written by build.sh inside the container at the moment
// the tree is compiled, so it is the only record of what was actually built.
// The conf remains the fallback for a build old enough to predate it.
//
// Plugins gain the sha they were built from, which is what this type's
// documentation has always promised and the code did not do: bare names say a
// plugin was present, not which one.
func (e *ManifestEntry) Provenance(builtSHA, confSHA string, pins map[string]string) {
	e.SHA = builtSHA
	if e.SHA == "" {
		// Only when the build left no record; a campaign that reused a build
		// from before BUILD-INFO existed is still better described by the conf
		// than by an empty field.
		e.SHA = confSHA
	}
	for i, name := range e.Plugins {
		if sha := pins[name]; sha != "" {
			e.Plugins[i] = name + "@" + sha
		}
	}
}

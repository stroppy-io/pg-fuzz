// Package breakdown attributes coverage and crashes to component x target.
//
// "A patched tree plus every plugin" is not one thing, and a single count per
// target cannot say which part produced it. Rows become the parts of the tree
// under test: PostgreSQL core, the core files the vendor patch touches, each
// extension the patch ships, and each out-of-tree plugin.
//
// HOW A PATH IS ATTRIBUTED
// ========================
// Every frame and every coverage record carries a source path, and the paths
// are unambiguous about which component they belong to:
//
//	src/backend/... , src/common/...      core
//	...but if the vendor patch touches
//	   that exact file                    core (patched)
//	contrib/<name>/...                    extension <name>  (shipped by the patch)
//	plugins/<name>/...                    plugin <name>     (out-of-tree)
//	/src/llvm-project/...                 the fuzzer runtime -- ignored
package breakdown

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var (
	reFrame      = regexp.MustCompile(`/src/[A-Za-z0-9_./+-]+\.(?:c|h|cpp|l|y)`)
	reCrashStart = regexp.MustCompile(`(ERROR: (?:AddressSanitizer|LeakSanitizer|libFuzzer)|` +
		`runtime error:|Direct leak of)`)
	rePatchTarget = regexp.MustCompile(`(?m)^\+\+\+ b?/?(\S+)`)
	rePlugin      = regexp.MustCompile(`^plugins/([A-Za-z0-9_-]+)/`)
	reContrib     = regexp.MustCompile(`^contrib/([A-Za-z0-9_-]+)/`)
	reBldParent   = regexp.MustCompile(`^/src/postgres/bld/\.\./`)
	rePGRoot      = regexp.MustCompile(`^/src/postgres/`)
	reBld         = regexp.MustCompile(`^bld/`)
)

// excluded paths are deliberately NOT attributed to any component.
//
// Not "unrecognised" -- DECIDED. Keeping the two apart is the point: anything
// that matches neither a component nor this list is a path shape nobody has
// ruled on, which is how 44,648 lines of generated core sources went missing
// without a word.
var excluded = []*regexp.Regexp{
	// The fuzzer's own runtime, which is not the software under test.
	regexp.MustCompile(`^/src/llvm-project/|compiler-rt`),
	// PostgreSQL's INSTALLED server headers, seen when a plugin or extension
	// compiles against the install tree. The same inline functions are already
	// counted from the main binary as src/include/...; attributing them here
	// as well would inflate core's denominator with duplicates of itself.
	regexp.MustCompile(`^/out/tmp_install/.*/include/server/`),
	regexp.MustCompile(`^/usr/include/`),
}

// Excluded reports whether a path is deliberately unattributed.
func Excluded(path string) bool {
	for _, rx := range excluded {
		if rx.MatchString(path) {
			return true
		}
	}
	return false
}

// PatchedFiles is the set of core files a workspace's patches touch.
func PatchedFiles(wsDir string) map[string]bool {
	out := map[string]bool{}
	b, err := os.ReadFile(filepath.Join(wsDir, "workspace.conf"))
	if err != nil {
		return out
	}
	for _, line := range strings.Split(string(b), "\n") {
		if !strings.HasPrefix(line, "patch=") {
			continue
		}
		for _, p := range strings.Fields(strings.SplitN(line, "=", 2)[1]) {
			raw, err := os.ReadFile(p)
			if err != nil {
				continue
			}
			for _, m := range rePatchTarget.FindAllStringSubmatch(string(raw), -1) {
				out[m[1]] = true
			}
		}
	}
	return out
}

// Classify maps one source path to a component, or "" if it is not under test.
func Classify(path string, patched map[string]bool) string {
	p := reBldParent.ReplaceAllString(path, "")
	p = rePGRoot.ReplaceAllString(p, "")
	// Generated sources genuinely LIVE in the build dir -- gram.c, scan.c, the
	// catalog headers -- and llvm-cov names them /src/postgres/bld/src/...,
	// which is not the bld/../ form the #line directives produce. Without this
	// they classified to nothing and were dropped: 95 files and 44,648 lines
	// of core's denominator, silently absent from every per-component number.
	p = reBld.ReplaceAllString(p, "")
	if strings.HasPrefix(p, "/src/llvm-project/") || strings.Contains(p, "compiler-rt") {
		return ""
	}
	if m := rePlugin.FindStringSubmatch(p); m != nil {
		return "plugin:" + m[1]
	}
	if m := reContrib.FindStringSubmatch(p); m != nil {
		return "ext:" + m[1]
	}
	if strings.HasPrefix(p, "src/") {
		// THE KEY IS STABLE; THE DISPLAY NAME IS NOT.
		//
		// Renaming this string would split the series: every historical row in
		// the component series carries "core (patched)", so a new name would
		// appear as a second, unrelated component. The honest label is applied
		// where the report renders it instead.
		//
		// It reads as "coverage of the patch" and is not. It is every line of
		// every FILE the patch touches: 265 files, 114,450 lines, of which the
		// vendor patch's own additions are 26,073 -- 22.8%. The other 77% is
		// pre-existing PostgreSQL that happens to share a file with a hunk.
		if patched[p] {
			return "core (patched)"
		}
		return "core"
	}
	return ""
}

// Metrics are the four llvm-cov reports per file.
var Metrics = []string{"lines", "functions", "regions", "branches"}

// Counts is a covered-of-total pair.
type Counts struct {
	Covered int `json:"covered"`
	Count   int `json:"count"`
}

// Aggregate turns an `llvm-cov export -summary-only` document into per-component
// totals.
//
// Files that Classify rejects -- the fuzzer runtime, system headers -- are
// DROPPED rather than bucketed into core, which would inflate core's
// denominator with code that is not under test.
func Aggregate(export []byte, patched map[string]bool) (map[string]map[string]Counts, error) {
	var doc struct {
		Data []struct {
			Files []struct {
				Filename string                     `json:"filename"`
				Summary  map[string]json.RawMessage `json:"summary"`
			} `json:"files"`
		} `json:"data"`
	}
	if err := json.Unmarshal(export, &doc); err != nil {
		return nil, err
	}
	out := map[string]map[string]Counts{}
	if len(doc.Data) == 0 {
		return out, nil
	}
	for _, f := range doc.Data[0].Files {
		comp := Classify(f.Filename, patched)
		if comp == "" {
			continue
		}
		if out[comp] == nil {
			out[comp] = map[string]Counts{}
		}
		for _, m := range Metrics {
			raw, ok := f.Summary[m]
			if !ok {
				continue
			}
			var c Counts
			if json.Unmarshal(raw, &c) != nil {
				continue
			}
			acc := out[comp][m]
			acc.Covered += c.Covered
			acc.Count += c.Count
			out[comp][m] = acc
		}
	}
	return out, nil
}

// Scan attributes each crash report in a workspace's run logs.
//
// A stack usually spans several components: an extension function called
// through the executor touches both. So a report is counted ONCE PER COMPONENT
// IT TOUCHES. Attributing only the innermost frame would credit everything to
// whichever leaf happened to fault, and attributing only the outermost would
// credit everything to core.
func Scan(wsDir string, only map[string]bool) map[string]map[string]int {
	patched := PatchedFiles(wsDir)
	out := map[string]map[string]int{}
	dirs, _ := filepath.Glob(filepath.Join(wsDir, "artifacts", "*_fuzzer"))
	sort.Strings(dirs)
	for _, tdir := range dirs {
		target := filepath.Base(tdir)
		if only != nil && !only[target] {
			continue
		}
		logs, _ := filepath.Glob(filepath.Join(tdir, "run-*.log.gz"))
		sort.Strings(logs)
		for _, lg := range logs {
			scanLog(lg, target, patched, out)
		}
	}
	return out
}

func scanLog(path, target string, patched map[string]bool, out map[string]map[string]int) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		return
	}
	defer zr.Close()

	credit := func(touched map[string]bool) {
		for c := range touched {
			if out[c] == nil {
				out[c] = map[string]int{}
			}
			out[c][target]++
		}
	}

	inReport := false
	touched := map[string]bool{}
	sc := bufio.NewScanner(zr)
	sc.Buffer(make([]byte, 0, 256*1024), 8*1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if reCrashStart.MatchString(line) {
			credit(touched)
			inReport, touched = true, map[string]bool{}
			continue
		}
		if !inReport {
			continue
		}
		if strings.HasPrefix(line, "SUMMARY") || strings.HasPrefix(line, "stat::") {
			credit(touched)
			inReport, touched = false, map[string]bool{}
			continue
		}
		for _, m := range reFrame.FindAllString(line, -1) {
			if c := Classify(m, patched); c != "" {
				touched[c] = true
			}
		}
	}
	credit(touched)
}

// ComponentsOf lists every component under test, from the workspace's own
// configuration.
//
// Listed whether or not it has ever appeared in a stack. A plugin with no
// findings is a fact worth showing -- it means that plugin is loaded and
// quiet, which is different from it not being there, and a table that hides
// the zeros cannot tell you which of the thirteen is which.
func ComponentsOf(wsDir string) []string {
	var plugins, exts []string
	if b, err := os.ReadFile(filepath.Join(wsDir, "workspace.conf")); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			switch {
			case strings.HasPrefix(line, "plugins="):
				for _, spec := range strings.Fields(strings.SplitN(line, "=", 2)[1]) {
					plugins = append(plugins, strings.SplitN(spec, "@", 2)[0])
				}
			case strings.HasPrefix(line, "extensions="):
				exts = strings.Fields(strings.SplitN(line, "=", 2)[1])
			}
		}
	}
	out := []string{"core"}
	if len(PatchedFiles(wsDir)) > 0 {
		out = append(out, "core (patched)")
	}
	for _, e := range exts {
		out = append(out, "ext:"+e)
	}
	for _, p := range plugins {
		out = append(out, "plugin:"+p)
	}
	return out
}

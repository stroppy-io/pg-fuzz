// Package triage generates the reporting triage document from the record.
//
// Everything is DERIVED: the finding list from the directories, the status and
// attribution from each README, the input inventory from what is actually on
// disk, and the unfiled-signature section from the campaign censuses
// cross-referenced against the UBSan accept-list.
//
// WHY A GENERATOR AND NOT A DOCUMENT
// ==================================
// The counts here are the same counts the campaign report publishes, and those
// drifted twice: `.git` was counted as a finding for as long as FINDINGS has
// been a git repo, and a defect reattributed to upstream PostgreSQL kept its
// orioledb- directory name and stayed in the storage column. Both are the kind
// of error a generator catches and prose does not, because a generator has to
// name its rule.
package triage

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// ---------------------------------------------------------------- curated
//
// Two tables are hand-maintained, and they are the only two.

// AttribOverride is a finding whose directory name is not its attribution.
//
// The directory is kept because renaming it breaks every link that points at
// it; the override records what the write-up actually concluded.
var AttribOverride = map[string][2]string{
	"orioledb-vacuum-error-path-leak": {
		"PostgreSQL core",
		"attribution overturned to upstream PostgreSQL 2026-08-16; the " +
			"directory name predates that and was never changed",
	},
}

// signatureFiled maps a crash signature to the finding that explains it, by
// substring. Anything unmatched is reported as unfiled.
//
// ORDER MATTERS, so this is a slice rather than a map: Go's map iteration is
// randomised, and two findings can produce the same signature.
var signatureFiled = []struct{ Token, Finding string }{
	{"guc-file.l", "config-file-nul-deescape"},
	{"xlogreader.c", "xlogreader-decode-overflow"},
	// Key on the FILE, never file:line -- the same assert moves line between
	// majors, which is the reason the UBSan gate keys on the function rather
	// than the site.
	{"instrument.c", "oss-fuzz-harness-bugs (sub-defect 13)"},
	{"nodes.h", "oss-fuzz-harness-bugs (sub-defect 1)"},
	{"latch.c", "oss-fuzz-harness-bugs (sub-defect 5)"},
	{"ErrorData", "oss-fuzz-harness-bugs (sub-defect 2)"},
	{"mcxt.c", "oss-fuzz-harness-bugs (sub-defect 14)"},
	{"libFuzzer timeout", "timeout-never-fires"},
	{"libFuzzer out-of-memory", "pg-timezone-cache-unbounded"},
	{"ASAN stack-overflow", "oss-fuzz-harness-bugs (sub-defect 12)"},
	// Same assert, two unrelated causes, told apart only by which target
	// produced it: extension_funcs is the mchar corruption, encoding is the
	// EUC_CN buffer overflowing into the allocator. A rule keyed on the
	// signature alone collapses them into whichever is listed first.
	{"memutils_memorychunk.h", "mchar-regex-chunk-corruption"},
	{"wchar.c", "encoding-fuzzer-euc-cn-overflow"},
	{"aset.c", "encoding-fuzzer-euc-cn-overflow"},
}

// signatureByTarget is consulted BEFORE signatureFiled, so a signature two
// findings can produce is attributed by the target that produced it rather
// than by list order.
var signatureByTarget = []struct{ Token, Target, Finding string }{
	{"memutils_memorychunk.h", "encoding", "encoding-fuzzer-euc-cn-overflow"},
	{"memutils_memorychunk.h", "extension_funcs", "mchar-regex-chunk-corruption"},
	{"aset.c", "encoding", "encoding-fuzzer-euc-cn-overflow"},
}

var (
	extPrefixes     = []string{"credcheck", "mchar", "orafce", "extension-funcs"}
	harnessPrefixes = []string{"budget-spent", "harness-", "oss-fuzz-harness",
		"timeout-never", "simple-query-executes", "slow-units", "encoding-fuzzer"}
)

// Areas is the report's four buckets, in the order they are printed.
var Areas = []string{"storage engine", "PostgreSQL core", "harness & tooling",
	"third-party extensions"}

// overflowClass names the UBSan reports the accept-list can excuse.
var overflowClass = []string{"signed integer overflow", "negation of"}

// leakPrefix marks LeakSanitizer output, which is a CLASS, not a list of
// defects.
//
// Leak detection was removed from the run path because these are dominated by
// allocations the harness never frees between inputs. Counted and summarised
// rather than listed as leads.
const leakPrefix = "LEAK in "

// SigClass ranks a signature by what kind of object it is. A memory-safety
// report on stock PostgreSQL is a different thing from an arithmetic one the
// accept-list has simply not catalogued yet.
func SigClass(sig string) string {
	switch {
	case strings.HasPrefix(sig, leakPrefix):
		return "leak"
	case strings.Contains(sig, "heap-buffer-overflow"),
		strings.Contains(sig, "use-after-free"),
		strings.Contains(sig, "SEGV"),
		strings.Contains(sig, "stack-overflow"):
		return "memory"
	case strings.HasPrefix(sig, "Assert("):
		return "assert"
	}
	for _, c := range overflowClass {
		if strings.Contains(sig, c) {
			return "arith"
		}
	}
	return "other"
}

// AreaOf places a finding in one of the four buckets.
func AreaOf(name string) string {
	if v, ok := AttribOverride[name]; ok {
		return v[0]
	}
	switch {
	case strings.HasPrefix(name, "orioledb-"):
		return "storage engine"
	case hasAnyPrefix(name, extPrefixes):
		return "third-party extensions"
	case hasAnyPrefix(name, harnessPrefixes):
		return "harness & tooling"
	}
	return "PostgreSQL core"
}

func hasAnyPrefix(s string, pres []string) bool {
	for _, p := range pres {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

var reDated = regexp.MustCompile(`^20\d\d-`)

// FindingDirs lists every finding directory.
//
// Dotfiles are NOT findings -- FINDINGS is its own git repo, so .git is a
// directory here, and counting it inflated the published headline by one.
func FindingDirs(root string) []string {
	ents, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range ents {
		n := e.Name()
		if !e.IsDir() || strings.HasPrefix(n, ".") || reDated.MatchString(n) || n == "reports" {
			continue
		}
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// InputsFor lists what a maintainer could actually run, and where it came from.
func InputsFor(root, name string) []string {
	d := filepath.Join(root, name)
	var out []string
	filepath.WalkDir(d, func(p string, e os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if e.IsDir() {
			if strings.HasPrefix(e.Name(), ".") && p != d {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(e.Name(), ".md") {
			return nil
		}
		rel, err := filepath.Rel(d, p)
		if err == nil {
			out = append(out, rel)
		}
		return nil
	})
	sort.Strings(out)
	return out
}

// FiledAs names the finding that explains a signature, if any.
func FiledAs(sig string, targets map[string]bool) string {
	for _, r := range signatureByTarget {
		if strings.Contains(sig, r.Token) && targets[r.Target] {
			return r.Finding
		}
	}
	for _, r := range signatureFiled {
		if strings.Contains(sig, r.Token) {
			return r.Finding
		}
	}
	return ""
}

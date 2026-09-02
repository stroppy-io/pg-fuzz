// Package findings reads the write-ups in FINDINGS/.
//
// TWO COUNTING BUGS THIS EXISTS TO NOT REPEAT
// ===========================================
// The published headline said 25 findings and it was 24: the scanner skipped
// dated snapshots and reports/ but not dotfiles, and FINDINGS/.git is a
// directory because FINDINGS is its own repository. It was counted as a
// PostgreSQL-core finding, and as "not attributable from the write-up" in the
// per-target table.
//
// And a defect reattributed to upstream PostgreSQL kept its orioledb-
// directory name, so it was counted under the storage engine for weeks. A
// directory is renamed only when every link into it can be updated, so until
// then the override below is what is true.
package findings

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Area is the bucket a finding is counted in.
type Area string

const (
	Storage    Area = "storage engine"
	Core       Area = "PostgreSQL core"
	Harness    Area = "harness & tooling"
	Extensions Area = "third-party extensions"
)

// Areas is the order they are reported in.
var Areas = []Area{Storage, Core, Harness, Extensions}

// Override records a finding whose directory name is no longer its
// attribution, with the reason. Judgement, made once, in a commit.
var Override = map[string]struct {
	Area Area
	Why  string
}{
	"orioledb-vacuum-error-path-leak": {Core,
		"attribution overturned to upstream PostgreSQL 2026-08-16; the " +
			"directory name predates that and was never changed"},
}

var (
	extPrefixes     = []string{"credcheck", "mchar", "orafce", "extension-funcs"}
	harnessPrefixes = []string{"budget-spent", "harness-", "oss-fuzz-harness",
		"timeout-never", "simple-query-executes", "slow-units", "encoding-fuzzer"}
	dated = regexp.MustCompile(`^20\d\d-`)
)

// Finding is one write-up.
type Finding struct {
	Name      string
	Area      Area
	Title     string
	Status    string
	FoundBy   string
	Cause     string
	Artifacts int
	Override  string // why this is not counted where its name suggests
}

// Scan reads every finding directory.
func Scan(root string) ([]Finding, error) {
	ents, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	var out []Finding
	for _, e := range ents {
		n := e.Name()
		if !e.IsDir() {
			continue
		}
		// Dotfiles are not findings. FINDINGS is its own git repository, so
		// .git is a directory here, and counting it inflated the published
		// headline by one for as long as that was true.
		if strings.HasPrefix(n, ".") || n == "reports" || dated.MatchString(n) {
			continue
		}
		f := Finding{Name: n, Area: areaOf(n)}
		if o, ok := Override[n]; ok {
			f.Override = o.Why
		}
		readMeta(filepath.Join(root, n), &f)
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func areaOf(name string) Area {
	if o, ok := Override[name]; ok {
		return o.Area
	}
	if strings.HasPrefix(name, "orioledb-") {
		return Storage
	}
	for _, p := range extPrefixes {
		if strings.HasPrefix(name, p) {
			return Extensions
		}
	}
	for _, p := range harnessPrefixes {
		if strings.HasPrefix(name, p) {
			return Harness
		}
	}
	return Core
}

var (
	reTitle  = regexp.MustCompile(`(?m)^#\s+(.+)$`)
	reField  = regexp.MustCompile(`(?m)^\*\*(Status|Found by|Cause):?\*\*:?\s*(.+)$`)
	reMDBold = regexp.MustCompile(`\*\*`)
)

func readMeta(dir string, f *Finding) {
	b, err := os.ReadFile(filepath.Join(dir, "README.md"))
	if err != nil {
		return
	}
	s := string(b)
	if m := reTitle.FindStringSubmatch(s); m != nil {
		f.Title = strings.TrimSpace(m[1])
	}
	for _, m := range reField.FindAllStringSubmatch(s, -1) {
		v := strings.TrimSpace(reMDBold.ReplaceAllString(m[2], ""))
		switch m[1] {
		case "Status":
			if f.Status == "" {
				f.Status = v
			}
		case "Found by":
			if f.FoundBy == "" {
				f.FoundBy = v
			}
		case "Cause":
			if f.Cause == "" {
				f.Cause = v
			}
		}
	}
	f.Artifacts = countArtifacts(dir)
}

func countArtifacts(dir string) int {
	n := 0
	filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if strings.HasSuffix(p, ".md") {
			return nil
		}
		n++
		return nil
	})
	return n
}

// ByArea counts findings per area.
func ByArea(fs []Finding) map[Area]int {
	m := map[Area]int{}
	for _, f := range fs {
		m[f.Area]++
	}
	return m
}

// ByTarget attributes findings to the fuzz target that found them.
//
// A write-up naming several targets is left as systemic on purpose: those hit
// many at once -- a timeout that never fires, a budget eaten by replay -- and
// pinning one on whichever is mentioned first would invent a precision the
// evidence does not have.
func ByTarget(fs []Finding) (per map[string]int, systemic, unattributed int) {
	per = map[string]int{}
	reTarget := regexp.MustCompile(`^` + "`?" + `([a-z_]+_fuzzer)` + "`?" + `$`)
	for _, f := range fs {
		v := strings.TrimSpace(f.FoundBy)
		switch {
		case v == "":
			unattributed++
		case strings.HasPrefix(v, "systemic"):
			systemic++
		case strings.HasPrefix(v, "unknown"):
			unattributed++
		default:
			if m := reTarget.FindStringSubmatch(v); m != nil {
				per[m[1]]++
			} else {
				systemic++
			}
		}
	}
	return per, systemic, unattributed
}

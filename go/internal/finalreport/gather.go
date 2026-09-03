// Package finalreport gathers and renders the campaign's snapshot report.
//
// GATHER AND RENDER ARE SEPARATE, IN THAT ORDER. The renderer reads the JSON
// the gather writes, so a report rendered from a stale gather is a report that
// describes a run that already ended -- and nothing about it looks wrong.
package finalreport

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"pgfuzz/internal/findings"
)

// Masked is what the gates chose NOT to fail on.
//
// A ratchet hides things by design, in three ways, and a report that only
// shows what passed is a report that hides them too:
//
//	acknowledgements  known-starved.tsv suppresses a target entirely. That is
//	                  correct -- an acked target is a decision made in a commit
//	                  -- but an ack nobody has revisited in months is a finding
//	                  nobody looked at.
//
//	the tolerance     the rule is `observed >= floor * 0.1`, which is "at least
//	                  a TENTH of the record", not "within 10% of it". A target
//	                  can fall by 80% and pass in silence.
//
//	regime skips      floors earned under a different job count are skipped as
//	                  not comparable. Necessary, and still masking: a target can
//	                  regress freely while its floor sits unenforced.
//
// None of this is wrong. All of it needs saying out loud.
type Masked struct {
	Acks          []Ack      `json:"acks"`
	Degraded      []Degraded `json:"degraded"`
	RegimeSkipped []Skipped  `json:"regime_skipped"`
}

// Ack is one row of known-starved.tsv.
type Ack struct {
	Target  string `json:"target"`
	Reason  string `json:"reason"`
	Ref     string `json:"ref"`
	Since   string `json:"since"`
	AgeDays *int   `json:"age_days"`
}

// Degraded is a target above the bar and far below its record -- the band the
// tolerance makes invisible.
type Degraded struct {
	WS       string  `json:"ws"`
	Target   string  `json:"target"`
	Observed int     `json:"observed"`
	Floor    int     `json:"floor"`
	Ratio    float64 `json:"ratio"`
}

// Skipped is a floor sitting unenforced because no regime was recorded for it.
type Skipped struct {
	WS     string `json:"ws"`
	Target string `json:"target"`
	Floor  int    `json:"floor"`
}

// MaskedInputs is where the three sources live.
type MaskedInputs struct {
	KnownStarved string
	Baseline     string
	Series       string
	Today        time.Time
}

// GatherMasked reads all three.
func GatherMasked(in MaskedInputs) Masked {
	out := Masked{Acks: []Ack{}, Degraded: []Degraded{}, RegimeSkipped: []Skipped{}}

	if b, err := os.ReadFile(in.KnownStarved); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
				continue
			}
			f := strings.Split(line, "\t")
			a := Ack{Target: f[0]}
			if len(f) > 1 {
				a.Reason = f[1]
			}
			if len(f) > 2 {
				a.Ref = f[2]
			}
			if len(f) > 3 {
				a.Since = f[3]
				if d, err := time.Parse("2006-01-02", strings.TrimSpace(f[3])); err == nil {
					n := int(in.Today.Sub(d).Hours() / 24)
					a.AgeDays = &n
				}
			}
			out.Acks = append(out.Acks, a)
		}
	}

	raw, err := os.ReadFile(in.Baseline)
	if err != nil {
		return out
	}
	var base struct {
		Tolerance float64                      `json:"tolerance"`
		Floors    map[string]map[string]int    `json:"floors"`
		Regimes   map[string]map[string]string `json:"regimes"`
	}
	if json.Unmarshal(raw, &base) != nil {
		return out
	}
	tol := base.Tolerance
	if tol == 0 {
		tol = 0.1
	}
	series := readSeries(in.Series)

	var wss []string
	for ws := range base.Floors {
		wss = append(wss, ws)
	}
	sort.Strings(wss)
	for _, ws := range wss {
		regs := base.Regimes[ws]
		latest := map[string]int{}
		for _, r := range series {
			if r.WS != ws {
				continue
			}
			for t, v := range r.Execs {
				if v != 0 {
					latest[t] = v
				}
			}
		}
		var ts []string
		for t := range base.Floors[ws] {
			ts = append(ts, t)
		}
		sort.Strings(ts)
		for _, t := range ts {
			fl := base.Floors[ws][t]
			obs, seen := latest[t]
			if fl == 0 || !seen {
				continue
			}
			ratio := float64(obs) / float64(fl)
			if tol <= ratio && ratio < 0.5 {
				out.Degraded = append(out.Degraded, Degraded{ws, t, obs, fl,
					math2(ratio)})
			}
			// A floor with NO recorded regime is the unenforced one. Only
			// meaningful once the workspace has regimes at all -- before that
			// nothing has been stamped and every floor would list.
			if len(regs) > 0 {
				if _, ok := regs[t]; !ok {
					out.RegimeSkipped = append(out.RegimeSkipped, Skipped{ws, t, fl})
				}
			}
		}
	}
	sort.SliceStable(out.Degraded, func(i, j int) bool {
		return out.Degraded[i].Ratio < out.Degraded[j].Ratio
	})
	return out
}

func math2(f float64) float64 {
	s := strconv.FormatFloat(f, 'f', 3, 64)
	v, _ := strconv.ParseFloat(s, 64)
	return v
}

type seriesRow struct {
	WS    string         `json:"ws"`
	Execs map[string]int `json:"execs"`
}

func readSeries(path string) []seriesRow {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []seriesRow
	dec := json.NewDecoder(f)
	for {
		var r seriesRow
		if err := dec.Decode(&r); err != nil {
			break
		}
		out = append(out, r)
	}
	return out
}

// Findings counts what the campaign turned up.
type Findings struct {
	ByCategory map[string]int `json:"by_category"`
	Total      int            `json:"total"`
	ByTarget   map[string]int `json:"by_target"`
	Systemic   int            `json:"systemic"`
	Other      int            `json:"other_targets"`
	Unattr     int            `json:"unattributed"`
}

var (
	reDated     = regexp.MustCompile(`^20\d\d-`)
	reTargetTok = regexp.MustCompile(`\b([a-z_]+_fuzzer)\b`)
)

// isFinding decides whether a directory under FINDINGS is one.
//
// Dotfiles are NOT findings. `.git` is a directory here -- FINDINGS is its own
// repo -- and counting it inflated the headline by one.
func isFinding(name string, isDir bool) bool {
	return isDir && !strings.HasPrefix(name, ".") &&
		!reDated.MatchString(name) && name != "reports"
}

// AttributionOverride is a finding whose directory name is no longer its
// attribution.
//
// Kept in step with the triage document, which explains each one; a directory
// is renamed only when every link into it can be updated, so until then the
// override is what is true.
var AttributionOverride = map[string]string{
	// The allocation site and the missing free are upstream PostgreSQL's;
	// attribution overturned, the directory name predates it.
	"orioledb-vacuum-error-path-leak": "PostgreSQL core",
}

var (
	extPrefixes = []string{"credcheck", "mchar", "orafce", "extension-funcs"}
	harnessPre  = []string{"budget-spent", "harness-", "oss-fuzz-harness",
		"timeout-never", "simple-query-executes", "slow-units", "encoding-fuzzer"}
)

// GatherFindings counts distinct triaged findings by component -- NOT named.
//
// Deliberately counts rather than lists. Naming which third-party extension
// carries a defect is an upstream attribution, and that is the maintainer's
// call to make, not this report's.
func GatherFindings(root string, known map[string]bool) Findings {
	f := Findings{
		ByCategory: map[string]int{"PostgreSQL core": 0, "storage engine": 0,
			"third-party extensions": 0, "harness & tooling": 0},
		ByTarget: map[string]int{},
	}
	ents, err := os.ReadDir(root)
	if err != nil {
		return f
	}
	names := make([]string, 0, len(ents))
	for _, e := range ents {
		if isFinding(e.Name(), e.IsDir()) {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	for _, n := range names {
		f.Total++
		switch {
		case AttributionOverride[n] != "":
			f.ByCategory[AttributionOverride[n]]++
		case strings.HasPrefix(n, "orioledb-"):
			f.ByCategory["storage engine"]++
		case hasAnyPrefix(n, extPrefixes):
			f.ByCategory["third-party extensions"]++
		case hasAnyPrefix(n, harnessPre):
			f.ByCategory["harness & tooling"]++
		default:
			f.ByCategory["PostgreSQL core"]++
		}

		// Attribution, by two rules in order: an explicit "**Found by:**"
		// line, else the write-up naming exactly ONE known target.
		//
		// A write-up naming several is left unattributed ON PURPOSE. Those are
		// not missing data -- they are systemic findings (a timeout that never
		// fires, a budget consumed by replay) that hit many targets at once,
		// and pinning them on whichever fuzzer is mentioned first would invent
		// a precision the evidence does not have.
		b, err := os.ReadFile(filepath.Join(root, n, "README.md"))
		if err != nil {
			f.Unattr++
			continue
		}
		txt := string(b)
		// The explicit field is AUTHORITATIVE, including when it says the
		// finding is systemic or unattributable. Only fall back to inferring
		// from prose for write-ups that predate the convention.
		// ONE PARSER, shared with the findings package. Two regexes for one
		// field agreed only because every write-up on disk happens to use the
		// form both accept.
		if v := findings.Field(txt, "Found by"); v != "" {
			if strings.HasPrefix(v, "systemic") {
				f.Systemic++
				continue
			}
			if strings.HasPrefix(v, "unknown") {
				f.Unattr++
				continue
			}
		}
		tgt := ""
		if m := reTargetTok.FindStringSubmatch(findings.Field(txt, "Found by")); m != nil {
			tgt = m[1]
		}
		if tgt == "" {
			seen := map[string]bool{}
			var found []string
			for _, m := range reTargetTok.FindAllStringSubmatch(txt, -1) {
				t := m[1]
				if (known[t] || t == "storage_fuzzer") && !seen[t] {
					seen[t] = true
					found = append(found, t)
				}
			}
			switch {
			case len(found) == 1:
				tgt = found[0]
			case len(found) > 1:
				f.Systemic++
				continue
			default:
				f.Unattr++
				continue
			}
		}
		// Targets outside this campaign's set (storage_fuzzer drives the
		// OrioleDB scenario harness) are counted SEPARATELY rather than
		// dropped.
		if known[tgt] {
			f.ByTarget[tgt]++
		} else {
			f.Other++
		}
	}
	return f
}

func hasAnyPrefix(s string, pres []string) bool {
	for _, p := range pres {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// Patch is one source modification in play, with provenance.
//
// Four kinds, and the distinction matters for anyone reading the report: a
// vendor patch we were given, an upstream cherry-pick, a local fix to a
// third-party extension, and our own harness code. Only the third kind could
// be mistaken for "we found a bug in someone else's software", and one of them
// explicitly is not that.
type Patch struct {
	Kind string `json:"kind"`
	Path string `json:"path"`
	Name string `json:"name,omitempty"`
	Note string `json:"note,omitempty"`
	Head string `json:"head,omitempty"`
}

var (
	rePatchEq = regexp.MustCompile(`patch=(\S+)`)
	reExtAt   = regexp.MustCompile(`([a-z_]+)@(/\S+)`)
)

// GatherPatches reads the workspace configuration and the harness history.
func GatherPatches(repo string, confPaths []string, harnessFiles []string) []Patch {
	conf := ""
	for _, p := range confPaths {
		if b, err := os.ReadFile(p); err == nil {
			conf = string(b)
			break
		}
	}
	var out []Patch
	for _, m := range rePatchEq.FindAllStringSubmatch(conf, -1) {
		for _, f := range strings.Split(m[1], ",") {
			out = append(out, Patch{Kind: "core patch", Path: f,
				Note: "applied to the PostgreSQL source before build"})
		}
	}
	for _, m := range reExtAt.FindAllStringSubmatch(conf, -1) {
		p := Patch{Kind: "patched extension", Path: m[2], Name: m[1]}
		if o, err := exec.Command("git", "-C", m[2], "log", "-1", "--format=%h %s").Output(); err == nil {
			p.Head = strings.TrimSpace(string(o))
		}
		out = append(out, p)
	}
	for _, f := range harnessFiles {
		rel := filepath.Join("project/fuzzer", f)
		if _, err := os.Stat(filepath.Join(repo, rel)); err != nil {
			continue
		}
		p := Patch{Kind: "harness", Path: rel}
		if o, err := exec.Command("git", "-C", repo, "log", "-1",
			"--format=%h %ad %s", "--date=short", "--", rel).Output(); err == nil {
			p.Head = strings.TrimSpace(string(o))
		}
		out = append(out, p)
	}
	return out
}

// HarnessFiles are the sources the report calls out by name.
var HarnessFiles = []string{"fuzz_deadline.h", "protocol_fuzzer.c",
	"simple_query_fuzzer.c", "spi_query_fuzzer.c", "fuzz_timeout.h"}

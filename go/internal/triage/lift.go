package triage

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// The lift: signatures seen on a VANILLA workspace that no finding explains.
//
// The point of running a vanilla arm alongside the forks is exactly this -- a
// fault landing on stock PostgreSQL is PostgreSQL's, whichever campaign
// happened to be running when it did.

// AcceptRow is one line of the UBSan accept-list.
type AcceptRow struct{ Fn, Scope, Site, Class string }

var reCFile = regexp.MustCompile(`\b([a-z_0-9]+\.c)\b`)

// AcceptedUBSan reads the files whose signed-overflow reports are accepted
// -fwrapv sites.
//
// The baseline keys on the innermost FUNCTION, deliberately -- file:line shifts
// under a minor release. A signature string carries file:line and not the
// function, so matching here is by FILE, which is coarser than the gate. Stated
// rather than hidden: this can only over-accept, so a site it calls accepted is
// one the gate has also seen.
func AcceptedUBSan(path string) (map[string]bool, []AcceptRow) {
	files := map[string]bool{}
	var rows []AcceptRow
	b, err := os.ReadFile(path)
	if err != nil {
		return files, rows
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}
		p := strings.Split(strings.TrimRight(line, "\n"), "\t")
		if len(p) < 4 {
			continue
		}
		rows = append(rows, AcceptRow{p[0], p[1], p[2], p[3]})
		if m := reCFile.FindStringSubmatch(p[2]); m != nil {
			files[m[1]] = true
		}
	}
	return files, rows
}

// CensusSig is one row of a campaign census.
type CensusSig struct {
	Signature  string   `json:"signature"`
	Families   []string `json:"families"`
	VanillaWS  []string `json:"vanilla_ws"`
	InOrioleDB bool     `json:"in_orioledb_code"`
	Targets    []string `json:"targets"`
	Hits       int      `json:"hits"`
}

// Census is one campaign's signature list.
type Census struct {
	Campaign string
	Sigs     []CensusSig
}

// Censuses reads every campaign census on disk, oldest name first.
//
// TWO LOCATIONS, for one reason: the census used to be written only into
// FINDINGS/<date>-<name>/, and report bundles carried counts instead. So the
// record was complete for early campaigns and empty after, and the vanilla-arm
// lift simply stopped at that date. Both are read, so a lift covers every
// campaign that recorded one rather than the first half of them.
func Censuses(findingsRoot, campaignsRoot string) []Census {
	var paths []string
	a, _ := filepath.Glob(filepath.Join(findingsRoot, "20*", "census", "signatures.json"))
	sort.Strings(a)
	b, _ := filepath.Glob(filepath.Join(campaignsRoot, "*", "*", "census", "signatures.json"))
	sort.Strings(b)
	paths = append(append(paths, a...), b...)

	var out []Census
	for _, p := range paths {
		raw, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		var sigs []CensusSig
		if json.Unmarshal(raw, &sigs) != nil {
			continue
		}
		parts := strings.Split(p, string(os.PathSeparator))
		out = append(out, Census{parts[len(parts)-3], sigs})
	}
	return out
}

// Lead is a signature with no finding behind it.
type Lead struct {
	Sig, Src  string
	Hits      int
	Camps     []string
	Vanilla   []string
	Targets   []string
	Fams      []string
	Overflow  bool
	Class     string
	Artefacts []Artefact
}

// Artefact is where a lead's crash inputs actually are.
type Artefact struct {
	Path string
	N    int
}

var reSrcFile = regexp.MustCompile(`\b([a-z_0-9]+\.(?:c|h))[:\s]`)

// ArtefactsFor finds a lead's kept crash inputs.
//
// A signature the census recorded is NOT the same as an artefact still on disk:
// the consolidation kept crash files per workspace and target, and not every
// campaign kept every one. A lead with nothing behind it cannot be re-run, and
// saying so is the difference between a list and a work queue.
func ArtefactsFor(findingsRoot, camp string, workspaces, targets []string) []Artefact {
	var out []Artefact
	ws := append([]string(nil), workspaces...)
	tg := append([]string(nil), targets...)
	sort.Strings(ws)
	sort.Strings(tg)
	for _, w := range ws {
		for _, t := range tg {
			d := filepath.Join(findingsRoot, camp, "reproducers", w, t+"_fuzzer")
			ents, err := os.ReadDir(d)
			if err != nil {
				continue
			}
			n := 0
			for _, e := range ents {
				if strings.HasPrefix(e.Name(), "crash-") {
					n++
				}
			}
			if n > 0 {
				out = append(out, Artefact{camp + "/reproducers/" + w + "/" + t + "_fuzzer", n})
			}
		}
	}
	return out
}

var classOrder = map[string]int{"memory": 0, "assert": 1, "arith": 2, "other": 3, "leak": 4}

// LiftCandidates finds signatures seen on a vanilla workspace, in the requested
// family, that no finding explains and the accept-list does not cover.
func LiftCandidates(findingsRoot, campaignsRoot, ubsanBaseline, family string) []Lead {
	accFiles, _ := AcceptedUBSan(ubsanBaseline)
	all := Censuses(findingsRoot, campaignsRoot)

	seen := map[string]*Lead{}
	var order []string
	for _, c := range all {
		for _, s := range c.Sigs {
			if !contains(s.Families, family) || len(s.VanillaWS) == 0 || s.InOrioleDB {
				continue
			}
			tg := map[string]bool{}
			for _, t := range s.Targets {
				tg[strings.TrimSuffix(t, "_fuzzer")] = true
			}
			if FiledAs(s.Signature, tg) != "" {
				continue
			}
			src := ""
			if m := reSrcFile.FindStringSubmatch(s.Signature); m != nil {
				src = m[1]
			}
			isOverflow := false
			for _, oc := range overflowClass {
				if strings.Contains(s.Signature, oc) {
					isOverflow = true
				}
			}
			if isOverflow && accFiles[src] {
				continue // an accepted -fwrapv site
			}
			e := seen[s.Signature]
			if e == nil {
				e = &Lead{Sig: s.Signature, Src: src, Overflow: isOverflow,
					Class: SigClass(s.Signature)}
				seen[s.Signature] = e
				order = append(order, s.Signature)
			}
			e.Hits += s.Hits
			e.Camps = addUnique(e.Camps, c.Campaign)
			for _, v := range s.VanillaWS {
				e.Vanilla = addUnique(e.Vanilla, v)
			}
			for _, t := range s.Targets {
				e.Targets = addUnique(e.Targets, strings.TrimSuffix(t, "_fuzzer"))
			}
			for _, f := range s.Families {
				e.Fams = addUnique(e.Fams, f)
			}
		}
	}

	// Where the crash inputs are, ACROSS EVERY CAMPAIGN that kept any for this
	// workspace/target pair -- not only the one the census came from.
	var out []Lead
	for _, k := range order {
		e := seen[k]
		for _, c := range all {
			e.Artefacts = append(e.Artefacts, ArtefactsFor(findingsRoot, c.Campaign, e.Vanilla, e.Targets)...)
		}
		out = append(out, *e)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if classOrder[out[i].Class] != classOrder[out[j].Class] {
			return classOrder[out[i].Class] < classOrder[out[j].Class]
		}
		return out[i].Hits > out[j].Hits
	})
	return out
}

func contains(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

func addUnique(xs []string, v string) []string {
	if contains(xs, v) {
		return xs
	}
	return append(xs, v)
}

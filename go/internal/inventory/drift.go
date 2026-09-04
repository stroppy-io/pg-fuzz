package inventory

import (
	"fmt"
	"sort"
	"strings"
)

// CROSS-EDITION DRIFT, which nothing checked.
//
// A campaign's workspaces are meant to be the same tree built three ways --
// address, undefined, coverage. When they are not, nothing fails: the coverage
// numbers sit beside the corpus numbers in one report describing two different
// programs.
//
// The documented case is 2026-08-27, when a -cov build was made from stock
// upstream orafce while the fuzzing builds used the patched tree. The shell's
// check-build-sync exited 1 on a differing pg_ref_sha, a differing patch set,
// or the same plugin at different commits. The port lists all of it and always
// exits 0.

// Edition is one workspace's build identity.
type Edition struct {
	Workspace string
	PGSHA     string
	Patches   string
	Plugins   map[string]string
}

// Drift is one disagreement between editions of the same tree.
type Drift struct {
	What   string // "pg_ref_sha", "patches", or "plugin:<name>"
	Values map[string]string
}

func (d Drift) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s differs across editions:", d.What)
	ws := make([]string, 0, len(d.Values))
	for w := range d.Values {
		ws = append(ws, w)
	}
	sort.Strings(ws)
	for _, w := range ws {
		v := d.Values[w]
		if v == "" {
			v = "(none)"
		}
		fmt.Fprintf(&b, "\n  %-28s %s", w, v)
	}
	return b.String()
}

// DriftIn compares editions that should be identical.
//
// ONLY WHAT IS PRESENT IS COMPARED. A workspace with no recorded pg_ref_sha
// has not been built, and calling that drift would fail every campaign with a
// workspace it has not got to yet -- the opposite of useful.
func DriftIn(eds []Edition) []Drift {
	var out []Drift

	pg := map[string]string{}
	pat := map[string]string{}
	plugins := map[string]map[string]string{}
	for _, e := range eds {
		if e.PGSHA != "" {
			pg[e.Workspace] = e.PGSHA
		}
		// Patches are compared only among workspaces that were built, for the
		// same reason: an unbuilt workspace records none.
		if e.PGSHA != "" {
			pat[e.Workspace] = e.Patches
		}
		for name, sha := range e.Plugins {
			if plugins[name] == nil {
				plugins[name] = map[string]string{}
			}
			plugins[name][e.Workspace] = sha
		}
	}
	if len(distinct(pg)) > 1 {
		out = append(out, Drift{What: "pg_ref_sha", Values: pg})
	}
	if len(distinct(pat)) > 1 {
		out = append(out, Drift{What: "patches", Values: pat})
	}
	names := make([]string, 0, len(plugins))
	for n := range plugins {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		// A plugin present in one edition and absent from another is not
		// drift in the plugin's commit -- it is a different configuration,
		// which the patches comparison above already covers.
		if len(plugins[n]) < 2 {
			continue
		}
		if len(distinct(plugins[n])) > 1 {
			out = append(out, Drift{What: "plugin:" + n, Values: plugins[n]})
		}
	}
	return out
}

func distinct(m map[string]string) map[string]bool {
	seen := map[string]bool{}
	for _, v := range m {
		seen[v] = true
	}
	return seen
}

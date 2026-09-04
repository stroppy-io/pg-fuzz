package tui

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"pgfuzz/internal/term"
)

// THE CAMPAIGN HISTORY, which `h` opened and the port dropped.
//
// The Python listed every consolidated run newest-first with its reproducer
// total, handling both the reproducers/ and findings/ layouts, and could open
// one to show its summary. The port's detail view is a per-workspace target
// table for the CURRENT run only, so a dashboard could not answer "what did
// the last five campaigns find" without leaving it.

// HistoryRow is one past run.
type HistoryRow struct {
	Slug        string
	When        string
	Workspaces  int
	Reproducers int
	Sealed      bool
	// Broken records a manifest that could not be read. Listed anyway: a run
	// missing from a history reads as a run that never happened.
	Broken bool
}

// History lists past campaigns, newest first.
func History(campaignsRoot string, limit int) []HistoryRow {
	ents, err := os.ReadDir(campaignsRoot)
	if err != nil {
		return nil
	}
	var out []HistoryRow
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		row := HistoryRow{Slug: e.Name()}
		b, err := os.ReadFile(filepath.Join(campaignsRoot, e.Name(), "MANIFEST.json"))
		if err != nil {
			// Not every campaign directory has one -- the older layout keeps
			// its manifests per run -- so this is "not read", not "corrupt".
			row.Broken = true
			out = append(out, row)
			continue
		}
		var m struct {
			Started string `json:"started"`
			Sealed  bool   `json:"sealed"`
			Entries []struct {
				Workspace string `json:"workspace"`
			} `json:"entries"`
		}
		if json.Unmarshal(b, &m) != nil {
			row.Broken = true
			out = append(out, row)
			continue
		}
		row.When, row.Sealed = m.Started, m.Sealed
		row.Workspaces = len(m.Entries)
		row.Reproducers = countArtifacts(filepath.Join(campaignsRoot, e.Name()))
		out = append(out, row)
	}
	// Newest first, by the recorded start rather than by mtime: a directory
	// touched by a later read is not a later run.
	sort.Slice(out, func(i, j int) bool {
		if out[i].When != out[j].When {
			return out[i].When > out[j].When
		}
		return out[i].Slug > out[j].Slug
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

// countArtifacts totals the reproducers a campaign kept, over both layouts.
func countArtifacts(slugDir string) int {
	n := 0
	for _, pat := range []string{
		filepath.Join(slugDir, "ws", "*", "artifacts", "*", "*"),
		filepath.Join(slugDir, "*", "artifacts", "*", "*"),
	} {
		hits, _ := filepath.Glob(pat)
		for _, h := range hits {
			if fi, err := os.Stat(h); err == nil && !fi.IsDir() && isArtifact(filepath.Base(h)) {
				n++
			}
		}
	}
	return n
}

func isArtifact(name string) bool {
	for _, p := range []string{"crash-", "oom-", "timeout-", "leak-"} {
		if len(name) > len(p) && name[:len(p)] == p {
			return true
		}
	}
	return false
}

func drawHistory(s *term.Screen, m Model) int {
	if len(m.History) == 0 {
		s.Line(4, term.Dim+"no other campaigns under this root"+term.Reset)
		return 6
	}
	s.Line(4, term.Bold+"  "+rpad("campaign", 34)+rpad("started", 22)+
		rjust("ws", 4)+rjust("reproducers", 14)+"  sealed"+term.Reset)
	row := 5
	for _, h := range m.History {
		if row >= s.Rows-2 {
			break
		}
		if h.Broken {
			s.Line(row, "  "+rpad(h.Slug, 34)+term.Dim+
				"manifest not read -- present, contents unknown"+term.Reset)
			row++
			continue
		}
		sealed := term.Dim + "no" + term.Reset
		if h.Sealed {
			sealed = "yes"
		}
		mark := ""
		if h.Slug == m.Slug {
			mark = term.Green + " <- this one" + term.Reset
		}
		s.Line(row, fmt.Sprintf("  %s%s%s%s  %s%s",
			rpad(h.Slug, 34), rpad(shortWhen(h.When), 22),
			rjust(fmt.Sprint(h.Workspaces), 4),
			rjust(comma(h.Reproducers), 14), sealed, mark))
		row++
	}
	return row + 1
}

// shortWhen trims an RFC3339 stamp to what fits, without pretending to parse
// something that may not be one.
func shortWhen(s string) string {
	if len(s) >= 19 {
		return s[:10] + " " + s[11:19]
	}
	return s
}

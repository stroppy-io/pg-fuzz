// Package report renders what a campaign did, as one self-contained page.
//
// SELF-CONTAINED, AND THAT IS NOT A STYLE CHOICE
// ==============================================
// The CSS is inlined and there are no external resources at all. An archived
// report has to render years later from a directory with no network, and the
// publishing path serves these under a policy that blocks external
// stylesheets -- a linked stylesheet does not degrade, it silently produces an
// unreadable page.
//
// TWO NUMBERS GET CALLED "FINDINGS"
// =================================
// An ARTIFACT is one saved input that made a target crash. A single defect hit
// repeatedly produces hundreds. A FINDING is a distinct defect after triage.
// Confusing them overstates the result by more than tenfold, so the page says
// both and labels which is which.
package report

import (
	"fmt"
	"html/template"
	"io"
	"time"

	"pgfuzz/internal/campaign"
	"pgfuzz/internal/coverage"
	"pgfuzz/internal/findings"
)

// Data is everything the page shows.
type Data struct {
	Slug      string
	Generated time.Time
	RunID     string
	Started   time.Time
	Elapsed   time.Duration

	Slices     int
	Rounds     int
	Execs      int
	NewInputs  int
	Artifacts  int
	Workspaces []WorkspaceRow

	// WHAT WAS UNDER TEST. A report is handed to somebody who was not here
	// and, increasingly, to a vendor being asked to fix something. Numbers
	// without the commit, the patch series and the plugin pins are not a
	// result -- they are a claim about an unnamed system. The manifest has
	// carried all of it since the campaign sealed it; the page did not show
	// any of it.
	UnderTest []UnderTestRow
	Sealed    bool

	Coverage     *coverage.Summary
	Findings     []findings.Finding
	ByArea       []AreaRow
	ByTarget     []TargetRow
	Systemic     int
	Unattributed int
}

// WorkspaceRow is one row of the per-workspace table.
type WorkspaceRow struct {
	Name      string
	Slices    int
	Execs     int
	NewInputs int
	Artifacts int
	Cov       int
}

// AreaRow is one bucket of findings.
type AreaRow struct {
	Area  string
	Count int
}

// TargetRow attributes findings to the target that found them.
type TargetRow struct {
	Target string
	Count  int
}

// Gather assembles the data from the record.
// UnderTestRow is one workspace's provenance, as the sealed manifest recorded
// it.
type UnderTestRow struct {
	Name      string
	Ref       string
	SHA       string
	Sanitizer string
	Plugins   []string
	Patches   []string
	BuildOK   bool
	Note      string
}

// WithManifest attaches what the campaign sealed about its own builds.
//
// Absent or unreadable is not fatal and not silent: the section simply does
// not render, rather than rendering empty and reading as "nothing was
// patched, no plugins, unknown commit".
func (d *Data) WithManifest(m campaign.Manifest) {
	d.Sealed = m.Sealed
	for _, e := range m.Entries {
		d.UnderTest = append(d.UnderTest, UnderTestRow{
			Name: e.Workspace, Ref: e.Ref, SHA: e.SHA,
			Sanitizer: e.Sanitizer, Plugins: e.Plugins,
			Patches: e.Patches, BuildOK: e.BuildOK, Note: e.Note,
		})
	}
}

func Gather(slug string, series campaign.Series, findingsRoot string, cov *coverage.Summary) (Data, error) {
	d := Data{Slug: slug, Generated: time.Now().UTC(), Coverage: cov}

	rows, err := series.Read()
	if err == nil {
		byWS := map[string]*WorkspaceRow{}
		rounds := map[int]bool{}
		for _, r := range rows {
			w := byWS[r.Workspace]
			if w == nil {
				w = &WorkspaceRow{Name: r.Workspace}
				byWS[r.Workspace] = w
			}
			w.Slices++
			w.Execs += r.Execs
			w.NewInputs += r.NewUnits
			w.Artifacts += r.Artifacts
			if r.Cov > w.Cov {
				w.Cov = r.Cov
			}
			rounds[r.Round] = true
			d.Execs += r.Execs
			d.NewInputs += r.NewUnits
			d.Artifacts += r.Artifacts
			if d.RunID == "" {
				d.RunID = r.RunID
			}
			if t, err := time.Parse(time.RFC3339, r.Started); err == nil {
				if d.Started.IsZero() || t.Before(d.Started) {
					d.Started = t
				}
			}
		}
		d.Slices = len(rows)
		d.Rounds = len(rounds)
		for _, w := range byWS {
			d.Workspaces = append(d.Workspaces, *w)
		}
		sortRows(d.Workspaces)
		if !d.Started.IsZero() {
			d.Elapsed = time.Since(d.Started)
		}
	}

	fs, err := findings.Scan(findingsRoot)
	if err == nil {
		d.Findings = fs
		by := findings.ByArea(fs)
		for _, a := range findings.Areas {
			d.ByArea = append(d.ByArea, AreaRow{string(a), by[a]})
		}
		per, systemic, unattributed := findings.ByTarget(fs)
		for t, n := range per {
			d.ByTarget = append(d.ByTarget, TargetRow{t, n})
		}
		sortTargets(d.ByTarget)
		d.Systemic, d.Unattributed = systemic, unattributed
	}
	return d, nil
}

func sortRows(r []WorkspaceRow) {
	for i := 1; i < len(r); i++ {
		for j := i; j > 0 && r[j].Name < r[j-1].Name; j-- {
			r[j], r[j-1] = r[j-1], r[j]
		}
	}
}

func sortTargets(r []TargetRow) {
	for i := 1; i < len(r); i++ {
		for j := i; j > 0 && r[j].Count > r[j-1].Count; j-- {
			r[j], r[j-1] = r[j-1], r[j]
		}
	}
}

// Render writes the page.
func Render(w io.Writer, d Data) error {
	t, err := template.New("report").Funcs(template.FuncMap{
		"comma": comma,
		// A commit is quoted at twelve characters everywhere in this project:
		// long enough to be unambiguous, short enough to read in a table.
		"short": func(sha string) string {
			if len(sha) > 12 {
				return sha[:12]
			}
			if sha == "" {
				return "—"
			}
			return sha
		},
		"pct": func(c coverage.Counted) string {
			return fmt.Sprintf("%.2f%%", c.Pct())
		},
		"dur": func(d time.Duration) string {
			if d <= 0 {
				return "—"
			}
			return fmt.Sprintf("%dh%02dm", int(d.Hours()), int(d.Minutes())%60)
		},
		"when": func(t time.Time) string {
			if t.IsZero() {
				return "—"
			}
			return t.Format("2006-01-02 15:04 MST")
		},
	}).Parse(page)
	if err != nil {
		return err
	}
	return t.Execute(w, d)
}

func comma(n int) string {
	s := fmt.Sprint(n)
	if len(s) <= 3 {
		return s
	}
	var out []byte
	for i := 0; i < len(s); i++ {
		if i > 0 && (len(s)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, s[i])
	}
	return string(out)
}

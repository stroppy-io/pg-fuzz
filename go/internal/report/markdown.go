package report

import (
	"fmt"
	"io"
	"strings"
	"time"
)

// RenderMarkdown writes the same report as Markdown.
//
// SAME DATA, one Gather. A second document assembled from a second reading of
// the record is how two reports of one campaign come to disagree, which this
// repository has now been bitten by three times. This takes the Data the HTML
// page takes and renders it; nothing here reads the record again.
//
// For reading on a phone, and for pasting into an issue: the HTML page is
// self-contained and therefore large, and neither of those places renders it.
func RenderMarkdown(w io.Writer, d Data) error {
	var b strings.Builder
	p := func(f string, v ...any) {
		if len(v) == 0 {
			b.WriteString(f)
			return
		}
		fmt.Fprintf(&b, f, v...)
	}

	p("# %s — fuzzing report\n\n", d.Slug)
	if d.RunID != "" {
		p("`%s`  \n", d.RunID)
	}
	p("Started %s · %s elapsed · rendered %s\n\n",
		whenStr(d.Started), durStr(d.Elapsed), whenStr(d.Generated))

	// ---- what was tested ------------------------------------------------
	if len(d.UnderTest) > 0 {
		p("## What was tested\n\n")
		p("As the campaign sealed it. The commit recorded is the one that was\n")
		p("*compiled*, not the branch name, which moves.\n\n")
		p("| workspace | ref | commit | sanitizer | patches | extensions |\n")
		p("|---|---|---|---|---|---|\n")
		for _, u := range d.UnderTest {
			name := "`" + u.Name + "`"
			if !u.BuildOK {
				name += " **(build failed)**"
			}
			p("| %s | `%s` | `%s` | %s | %s | %s |\n",
				name, u.Ref, short12(u.SHA), dashIf(u.Sanitizer),
				codeList(u.Patches), codeList(u.Plugins))
		}
		p("\n")
		if !d.Sealed {
			p("> **This campaign was not sealed.** It shared each workspace's corpus,\n")
			p("> so its coverage cannot be re-measured from this slug alone.\n\n")
		}
	}

	// ---- what the run did -----------------------------------------------
	p("## What the run did\n\n")
	p("| | |\n|---|---:|\n")
	p("| executions | %s |\n", comma(d.Execs))
	p("| new inputs | %s |\n", comma(d.NewInputs))
	p("| slices | %d in %d round(s) |\n", d.Slices, d.Rounds)
	p("| raw artifacts | %d |\n\n", d.Artifacts)
	p("> **An artifact is not a finding.** One saved input that made a target\n")
	p("> crash — and a single defect hit repeatedly produces hundreds. A finding\n")
	p("> is a distinct defect after triage. Confusing the two overstates a result\n")
	p("> by more than tenfold.\n\n")

	if len(d.Workspaces) > 0 {
		p("| workspace | slices | executions | new | artifacts | edges |\n")
		p("|---|---:|---:|---:|---:|---:|\n")
		for _, w := range d.Workspaces {
			p("| `%s` | %d | %s | %s | %d | %s |\n",
				w.Name, w.Slices, comma(w.Execs), comma(w.NewInputs), w.Artifacts, comma(w.Cov))
		}
		p("\n")
	}

	// ---- what this run found ---------------------------------------------
	//
	// SEPARATE FROM "Findings on record" BELOW, which are the project's
	// standing, triaged write-ups and belong to no single run. This is what
	// these logs said, and before it existed the answer for a UBSan build was
	// the artifact count -- structurally zero, because UBSan does not abort
	// and libFuzzer therefore never saves an input.
	if d.Scanned {
		p("## What this run found\n\n")
		if len(d.Signatures) == 0 {
			p("The run's own logs were scanned and produced **no signature**.\n\n")
			p("> That is a result, not a blank. It means the logs were read and\n")
			p("> nothing in them matched a crash, a sanitizer report or an\n")
			p("> out-of-memory — which is different from a run whose logs were\n")
			p("> never read, and this section would be absent in that case.\n\n")
		} else {
			p("**%d distinct signature(s)** in this run's own logs.\n\n", len(d.Signatures))
			p("> Distinct SIGNATURES, not findings and not artifacts. A signature is\n")
			p("> one site the logs reported, deduplicated across every slice that hit\n")
			p("> it; a finding is what a person writes after triage. A UBSan run\n")
			p("> reports sites here and zero artifacts above, because UBSan does not\n")
			p("> abort and so nothing is ever saved to disk.\n\n")
			p("| signature | hits | targets |\n|---|---:|---|\n")
			for _, sg := range d.Signatures {
				p("| %s | %d | %s |\n", sg.Signature, sg.Hits, strings.Join(sg.Targets, ", "))
			}
			p("\n")
		}
	}

	// ---- coverage --------------------------------------------------------
	if c := d.Coverage; c != nil {
		p("## Coverage\n\nAll %d targets combined, each line counted once.\n\n", c.Targets)
		p("| measure | covered | total | share |\n|---|---:|---:|---:|\n")
		p("| lines | %s | %s | %.2f%% |\n", comma(c.Lines.Covered), comma(c.Lines.Count), c.Lines.Pct())
		p("| functions | %s | %s | %.2f%% |\n", comma(c.Functions.Covered), comma(c.Functions.Count), c.Functions.Pct())
		p("| regions | %s | %s | %.2f%% |\n", comma(c.Regions.Covered), comma(c.Regions.Count), c.Regions.Pct())
		p("| branches | %s | %s | %.2f%% |\n\n", comma(c.Branches.Covered), comma(c.Branches.Count), c.Branches.Pct())
	}

	// ---- findings --------------------------------------------------------
	if len(d.Findings) > 0 {
		p("## Findings on record\n\n**%d distinct findings, triaged.**\n\n", len(d.Findings))
		p("> These are the project's standing findings, not this run's alone. A\n")
		p("> finding is a write-up a person made after triage, and write-ups are not\n")
		p("> stamped with the campaign that produced them — so they cannot be\n")
		p("> attributed to one run. What *this* run produced is the artifact count\n")
		p("> above.\n\n")

		if len(d.ByArea) > 0 {
			p("### By area\n\n| area | findings |\n|---|---:|\n")
			for _, a := range d.ByArea {
				p("| %s | %d |\n", a.Area, a.Count)
			}
			p("\n")
		}
		if len(d.ByTarget) > 0 {
			p("### By fuzzer\n\n| target | findings |\n|---|---:|\n")
			for _, t := range d.ByTarget {
				p("| `%s` | %d |\n", t.Target, t.Count)
			}
			if d.Systemic > 0 {
				p("| *systemic — several targets at once* | %d |\n", d.Systemic)
			}
			if d.Unattributed > 0 {
				p("| *unattributed* | %d |\n", d.Unattributed)
			}
			p("\n")
			p("> A write-up naming several targets is left systemic on purpose. Those\n")
			p("> hit many at once, and pinning one on whichever target is mentioned\n")
			p("> first would invent a precision the evidence does not have.\n\n")
		}

		p("### Each finding\n\n")
		for _, f := range d.Findings {
			title := f.Title
			if title == "" {
				title = f.Name
			}
			p("#### %s\n\n", title)
			p("`%s`\n\n", f.Name)
			row := func(k, v string) {
				if strings.TrimSpace(v) != "" {
					p("- **%s:** %s\n", k, v)
				}
			}
			row("Area", string(f.Area))
			row("Status", f.Status)
			row("Found by", f.FoundBy)
			row("Cause", f.Cause)
			if f.Artifacts > 0 {
				p("- **Artifacts:** %d\n", f.Artifacts)
			}
			if f.Override != "" {
				p("- **Not counted where its name suggests:** %s\n", f.Override)
			}
			p("\n")
		}
	}

	p("---\n\nGenerated by `pgfuzz report -md`.\n")
	_, err := io.WriteString(w, b.String())
	return err
}

// whenStr and durStr match what the HTML page prints, so the two documents
// describe one run in one vocabulary.
func whenStr(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	return t.UTC().Format("2006-01-02 15:04 UTC")
}

func durStr(d time.Duration) string {
	if d <= 0 {
		return "—"
	}
	return fmt.Sprintf("%dh%02dm", int(d.Hours()), int(d.Minutes())%60)
}

func short12(sha string) string {
	if sha == "" {
		return "—"
	}
	if len(sha) > 12 {
		return sha[:12]
	}
	return sha
}

func dashIf(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

// codeList renders a list as inline code, or an em dash when empty. Empty and
// "none recorded" are the same thing here and both are worth saying out loud.
func codeList(v []string) string {
	if len(v) == 0 {
		return "*none*"
	}
	out := make([]string, 0, len(v))
	for _, s := range v {
		out = append(out, "`"+s+"`")
	}
	return strings.Join(out, " ")
}

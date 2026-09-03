package finalreport

import (
	"fmt"
	"io"
	"sort"
	"strings"
)

// RenderMarkdown writes the soak report as Markdown.
//
// FROM THE ARCHIVED DATA, like Render, and for the same reason. The findings
// corpus under FINDINGS/ keeps moving -- a run archived on 2026-08-28 counted
// eight storage-engine findings and seven for the harness, and the same
// directory today gives seven and seven. Re-deriving a past run's numbers from
// today's corpus would quietly restate what that run found. Everything here
// comes from the data.json the run shipped.
//
// The HTML page is self-contained and therefore large; neither a phone nor an
// issue tracker renders it.
func RenderMarkdown(out io.Writer, in RenderInputs) error {
	d := in.Data
	var b strings.Builder
	p := func(f string, v ...any) { fmt.Fprintf(&b, f, v...) }

	p("# PostgreSQL fuzzing — soak report\n\n")
	if d.Generated != "" {
		p("Generated %s", d.Generated)
	}
	if in.StoppedAt != "" {
		p(" · campaign stopped %s", in.StoppedAt)
	}
	p("\n\n")

	// ---- runtime ---------------------------------------------------------
	rt := d.Runtime
	if rt.Slices > 0 || rt.Runs > 0 {
		p("## The run\n\n| | |\n|---|---:|\n")
		p("| runs | %d |\n", rt.Runs)
		p("| slices | %s |\n", commaI(rt.Slices))
		if rt.MachineHours != nil {
			p("| machine hours | %.1f |\n", *rt.MachineHours)
		}
		p("| active hours | %.1f |\n", rt.ActiveHours)
		if rt.First != "" {
			p("| first slice | %s |\n", rt.First)
		}
		if rt.Last != "" {
			p("| last slice | %s |\n", rt.Last)
		}
		p("\n")
	}

	// ---- what was tested -------------------------------------------------
	if len(d.Workspaces) > 0 {
		p("## Workspaces\n\n| workspace | targets | corpus | executions | new units | reproducers |\n")
		p("|---|---:|---:|---:|---:|---:|\n")
		for _, name := range sortedKeys(d.Workspaces) {
			ws := d.Workspaces[name]
			var execs, newUnits, arts int
			for _, t := range ws.Targets {
				execs += t.Log.Execs
				newUnits += t.Log.NewUnits
				for _, n := range t.Artifacts {
					arts += n
				}
			}
			p("| `%s` | %d | %s | %s | %s | %s |\n", name, len(ws.Targets),
				commaI(ws.CorpusTotal), commaI(execs), commaI(newUnits), commaI(arts))
		}
		p("\n")
		p("> **An artifact is not a finding.** A single defect hit repeatedly\n")
		p("> produces hundreds of reproducers. The finding count below is distinct\n")
		p("> defects after triage.\n\n")
	}

	// ---- patches and extensions -----------------------------------------
	if len(d.Patches) > 0 {
		p("## Patches and extensions applied\n\n| kind | name | source | head |\n|---|---|---|---|\n")
		for _, pt := range d.Patches {
			p("| %s | %s | `%s` | %s |\n",
				dash(pt.Kind), dash(pt.Name), pt.Path, dash(pt.Head))
		}
		p("\n")
	}

	// ---- coverage --------------------------------------------------------
	if u := in.Union; u != nil {
		p("## Coverage\n\nEvery per-target profile merged, each line counted once.\n\n")
		p("| measure | covered | total | share |\n|---|---:|---:|---:|\n")
		p("| lines | %s | %s | %s |\n", commaI(u.Lines.Covered), commaI(u.Lines.Count), pctOf(u.Lines))
		p("| functions | %s | %s | %s |\n", commaI(u.Functions.Covered), commaI(u.Functions.Count), pctOf(u.Functions))
		p("| branches | %s | %s | %s |\n\n", commaI(u.Branches.Covered), commaI(u.Branches.Count), pctOf(u.Branches))
	}

	// ---- findings --------------------------------------------------------
	f := d.Findings
	if f.Total > 0 {
		p("## Findings\n\n**%d distinct findings, triaged.**\n\n", f.Total)

		if len(f.ByCategory) > 0 {
			p("### By area\n\n| area | findings |\n|---|---:|\n")
			for _, k := range sortedCount(f.ByCategory) {
				p("| %s | %d |\n", k, f.ByCategory[k])
			}
			p("\n")
		}
		if len(f.ByTarget) > 0 {
			p("### By fuzzer\n\n| target | findings |\n|---|---:|\n")
			for _, k := range sortedCount(f.ByTarget) {
				p("| `%s` | %d |\n", k, f.ByTarget[k])
			}
			if f.Other > 0 {
				p("| *other targets* | %d |\n", f.Other)
			}
			if f.Systemic > 0 {
				p("| *systemic — several targets at once* | %d |\n", f.Systemic)
			}
			if f.Unattr > 0 {
				p("| *unattributed* | %d |\n", f.Unattr)
			}
			p("\n")
			p("> A write-up naming several targets is left systemic on purpose. Those\n")
			p("> hit many at once, and pinning one on whichever target is mentioned\n")
			p("> first would invent a precision the evidence does not have.\n\n")
		}
	}

	// ---- what the gates let through -------------------------------------
	m := d.Masked
	if n := len(m.Acks) + len(m.Degraded) + len(m.RegimeSkipped); n > 0 {
		p("## What the gates let through\n\n")
		p("Every rule that stops a ratchet crying wolf also hides something.\n\n")
		p("| how | targets |\n|---|---:|\n")
		p("| acknowledged | %d |\n", len(m.Acks))
		p("| under half their floor | %d |\n", len(m.Degraded))
		p("| no comparable floor | %d |\n", len(m.RegimeSkipped))
		p("| **total masked** | **%d** |\n\n", n)
		if len(m.Acks) > 0 {
			p("### Acknowledged\n\n| target | reason | since | age |\n|---|---|---|---:|\n")
			for _, a := range m.Acks {
				age := "—"
				if a.AgeDays != nil {
					age = fmt.Sprintf("%d days", *a.AgeDays)
				}
				p("| `%s` | %s | %s | %s |\n", a.Target, dash(a.Reason), dash(a.Since), age)
			}
			p("\n")
		}
	}

	p("---\n\nGenerated by `pgfuzz report -final -md`.\n")
	_, err := io.WriteString(out, b.String())
	return err
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// sortedCount orders by count descending, then by name, so the table reads
// biggest first and does not reshuffle between renders on a tie.
func sortedCount(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool {
		if m[out[i]] != m[out[j]] {
			return m[out[i]] > m[out[j]]
		}
		return out[i] < out[j]
	})
	return out
}

// pctOf renders a share, or an em dash when the denominator is zero -- an
// unmeasured quantity is not nought per cent.
func pctOf(c CovCounts) string {
	v, ok := pct(c.Covered, c.Count)
	if !ok {
		return "—"
	}
	return fmt.Sprintf("%.2f%%", v)
}

func dash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "—"
	}
	return s
}

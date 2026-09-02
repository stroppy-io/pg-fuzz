package finalreport

import (
	"sort"
	"strings"
)

func renderRuntime(o w, rt Runtime) {
	if rt.Slices == 0 {
		return
	}
	o.s(`<section id="runtime"><h2>How long it ran</h2>`)
	o.s(`<div class="figures">`)
	o.p("<div class=\"fig\"><span class=\"v\">%.1f h</span><span class=\"k\">last run</span></div>\n", rt.LastRunHours)
	o.p("<div class=\"fig\"><span class=\"v\">%.0f h</span><span class=\"k\">all runs</span></div>\n", rt.ActiveHours)
	o.p("<div class=\"fig\"><span class=\"v\">%s</span><span class=\"k\">slices of work</span></div>\n", commaI(rt.Slices))
	ch := rt.CoreHours
	if ch == nil {
		ch = rt.CoreHoursEst
	}
	if ch != nil {
		o.p("<div class=\"fig\"><span class=\"v\">%.0f</span>"+
			"<span class=\"k\">core-hours of machine</span></div>\n", *ch)
	}
	o.s(`</div>`)
	o.s(`<div class="wrap"><table class="cells"><tr><th></th><th>Runs</th>` +
		`<th>Slices</th><th>Hours</th><th>Period</th></tr>`)
	o.p("<tr><td class=\"t\">Most recent run</td><td>1</td><td>%s</td><td>%.1f</td>"+
		"<td>%s &rarr; %s</td></tr>\n",
		commaI(rt.LastRunSlices), rt.LastRunHours,
		esc(shortStamp(rt.LastRunStart)), esc(shortStamp(rt.LastRunEnd)))
	o.p("<tr><td class=\"t\">Whole campaign</td><td>%d</td><td>%s</td><td>%.0f</td>"+
		"<td>%s &rarr; %s</td></tr>\n",
		rt.Runs, commaI(rt.Slices), rt.ActiveHours,
		esc(shortStamp(rt.First)), esc(shortStamp(rt.Last)))
	o.s(`</table></div>`)
	o.p("<div class=\"nb\">Runs are detected from the slices themselves &mdash; nothing "+
		"records where one campaign ends and the next begins, but a slice lasts at "+
		"least 900s, so an hour in which none STARTED means nothing was running. The "+
		"hours column sums those run spans and therefore excludes the gaps between "+
		"them: first slice to last is %.0f hours, against %.0f of actual running. "+
		"Processor time actually spent fuzzing is the stricter measure again and is "+
		"not stated &mdash; the per-slice budget was not recorded before 2026-08-30 "+
		"(%s of %s rows carry it so far).</div>\n",
		rt.SpanHours, rt.ActiveHours, commaI(rt.SlicesTimed), commaI(rt.Slices))
	if rt.CoreHoursEst != nil && rt.CoreHours == nil {
		o.p("<div class=\"nb\"><b>%.0f core-hours</b> is how much machine the campaign "+
			"was given: %s. The multiplication is exact; what is estimated is only "+
			"that these rows carried no budget of their own, and the figure is "+
			"offered because every slice log still on disk agrees on the cost. Had "+
			"they disagreed, nothing would appear here rather than an average over a "+
			"mixed population.</div>\n", *rt.CoreHoursEst, esc(rt.CoreHoursBasis))
		o.s(`<div class="nb">That is machine ALLOCATED, not processor time burned, ` +
			`and the two diverge enormously by target. Measured this session: ` +
			`<code>spi_query</code> ran at 94&ndash;100% of a core while ` +
			`<code>simple_query</code> sat at 2&ndash;7%, waiting on the backend ` +
			`rather than computing. Consumption is sampled nowhere, and the ` +
			`containers are <code>--rm</code>, so their cgroup counters go with ` +
			`them.</div>`)
	}
	o.s(`</section>`)
}

// shortStamp keeps the date and the clock, dropping the seconds and the T.
func shortStamp(s string) string {
	if len(s) > 16 {
		s = s[:16]
	}
	return strings.Replace(s, "T", " ", 1)
}

func renderCells(o w, d Data, in RenderInputs, targets []string,
	cov map[string]CoverageRow, fper map[string]int) {

	o.s(`<section id="cells"><h2>Every target</h2>`)
	o.s(`<div class="eli5"><p>One entry per fuzz target. <b>Corpus</b> is how many inputs that target ` +
		`has kept. <b>Execs</b> is how many inputs it ran in its final slice. <b>New</b> is how many of ` +
		`those reached code nothing had reached before &mdash; a low number late in a long run is ` +
		`expected and means the easy ground is covered. <b>Floor</b> is the ratchet floor explained ` +
		`below.</p></div>`)
	o.s(`<div class="wrap"><table class="cells"><tr><th>Target</th>` +
		`<th>ASan corpus</th><th>ASan execs</th><th>ASan new</th>` +
		`<th>UBSan corpus</th><th>UBSan execs</th><th>UBSan new</th>` +
		`<th>Artifacts</th><th>Findings</th></tr>`)
	for _, t := range targets {
		a := d.Workspaces[Builds[0][0]].Targets[t]
		u := d.Workspaces[Builds[1][0]].Targets[t]
		art := 0
		for _, e := range []TargetRow{a, u} {
			for _, v := range e.Artifacts {
				art += v
			}
		}
		artS, findS := "&mdash;", "&mdash;"
		if art != 0 {
			artS = commaI(art)
		}
		if fper[t] != 0 {
			findS = commaI(fper[t])
		}
		o.p("<tr><td class=\"t\">%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n",
			esc(shortName(t)), corpusOrDash(a), num(a.SeriesExecs), num(a.SeriesNewUnits),
			corpusOrDash(u), num(u.SeriesExecs), num(u.SeriesNewUnits), artS, findS)
	}
	o.s(`</table></div>`)

	for _, t := range targets {
		a := d.Workspaces[Builds[0][0]].Targets[t]
		u := d.Workspaces[Builds[1][0]].Targets[t]
		feeds, reaches := "&mdash;", "&mdash;"
		if v, ok := Desc[t]; ok {
			feeds, reaches = v[0], v[1]
		}
		o.p("<div class=\"tgt\"><h3 id=\"t-%s\">%s</h3>\n", esc(t), esc(t))
		o.p("<p class=\"feeds\"><b>Input:</b> %s. <b>Reaches:</b> %s.</p>\n", esc(feeds), esc(reaches))
		o.s(`<div class="kv">`)
		o.p("<div><span class=\"v\">%s</span><span class=\"k\">ASan corpus</span></div>\n", corpusOrDash(a))
		o.p("<div><span class=\"v\">%s</span><span class=\"k\">UBSan corpus</span></div>\n", corpusOrDash(u))
		o.p("<div><span class=\"v\">%s</span><span class=\"k\">ASan execs (slice)</span></div>\n", num(a.SeriesExecs))
		o.p("<div><span class=\"v\">%s</span><span class=\"k\">UBSan execs (slice)</span></div>\n", num(u.SeriesExecs))
		o.p("<div><span class=\"v\">%s</span><span class=\"k\">exec floor</span></div>\n", num(a.ExecFloor))
		rfS := "&mdash;"
		if rf, ok := in.RateFloors[Builds[0][0]][t]; ok && rf != 0 {
			rfS = f0(rf)
		}
		o.p("<div><span class=\"v\">%s</span><span class=\"k\">rate floor /s</span></div>\n", rfS)
		if fper[t] != 0 {
			o.p("<div><span class=\"v\">%s</span><span class=\"k\">triaged findings</span></div>\n", commaI(fper[t]))
		}
		for _, p := range [][2]string{{"crashes", "crash"}, {"OOMs", "oom"}, {"timeout", "timeout"}} {
			tot := a.Artifacts[p[1]] + u.Artifacts[p[1]]
			if tot != 0 {
				o.p("<div><span class=\"v\">%s</span><span class=\"k\">%s (raw)</span></div>\n",
					commaI(tot), p[0])
			}
		}
		c, has := cov[t]
		if !has {
			o.s(`<div><span class="v dim">pending</span><span class="k">coverage</span></div>`)
		} else {
			o.p("<div><span class=\"v\">%s</span><span class=\"k\">lines covered</span></div>\n",
				commaI(c.Lines.Covered))
			if p, ok := pct(c.Lines.Covered, c.Lines.Count); ok {
				o.p("<div><span class=\"v\">%.2f%%</span><span class=\"k\">of the lines it links</span></div>\n", p)
			}
		}
		o.s(`</div>`)
		if a.CorpusArchived != 0 || u.CorpusArchived != 0 {
			o.p("<div class=\"nb\">Archived inputs held aside from an earlier corpus cap: "+
				"ASan %s, UBSan %s. These were moved, not deleted.</div>\n",
				commaI(a.CorpusArchived), commaI(u.CorpusArchived))
		}
		o.s(`</div>`)
	}
	o.s(`</section>`)
}

func shortName(t string) string { return strings.TrimSuffix(t, "_fuzzer") }

// corpusOrDash keeps a target that exists with an empty corpus distinct from
// one that is not in this build at all.
func corpusOrDash(r TargetRow) string {
	if r.Artifacts == nil && r.Corpus == 0 && r.SeriesRows == 0 {
		return "&mdash;"
	}
	return commaI(r.Corpus)
}

func renderCoverage(o w, d Data, in RenderInputs, targets []string,
	cov, covStale map[string]CoverageRow) {

	o.s(`<section id="coverage"><h2>Coverage</h2>`)
	o.s(`<div class="eli5"><p><b>Coverage</b> is the share of the program's lines that the ` +
		`corpus actually executes. It answers a question the corpus size cannot: are these inputs ` +
		`reaching the code we care about, or piling up in one corner?</p>` +
		`<p>It is measured after the run by replaying the finished corpus against a build compiled ` +
		`to record which lines execute. Each target is measured on its own, one at a time.</p>` +
		`<p><b>Compare the &ldquo;lines covered&rdquo; column, not the percentage.</b> Every target ` +
		`links a different set of source files, so each has its own denominator: most sit near ` +
		`550,000 lines of server code, but a target linking only the client library has a base of ` +
		`about 16,000. A percentage tracks one target over time; across targets it compares two ` +
		`different questions and will rank them wrongly.</p></div>`)

	want := targets
	if u := in.Union; u != nil && u.Lines.Count > 0 {
		l, f, b, e := u.Lines, u.Functions, u.Branches, u.LinesInEnteredFiles
		o.s(`<h3>All 23 together</h3>`)
		o.s(`<p>Per-target numbers cannot be added up: every target executes the server's ` +
			`startup, its allocator, its error paths, so summing would count those lines ` +
			`twenty-three times. This is the <b>union</b>, computed by merging the raw profile ` +
			`data and counting each line once no matter how many targets reached it.</p>`)
		o.s(`<div class="figures">`)
		o.p("<div class=\"fig\"><span class=\"v\">%.2f%%</span><span class=\"k\">of all lines</span></div>\n",
			100*float64(l.Covered)/float64(maxI(l.Count, 1)))
		if f.Count > 0 || f.Covered > 0 {
			o.p("<div class=\"fig\"><span class=\"v\">%.1f%%</span><span class=\"k\">of functions</span></div>\n",
				100*float64(f.Covered)/float64(maxI(f.Count, 1)))
		}
		if b.Count > 0 || b.Covered > 0 {
			o.p("<div class=\"fig\"><span class=\"v\">%.1f%%</span><span class=\"k\">of branches</span></div>\n",
				100*float64(b.Covered)/float64(maxI(b.Count, 1)))
		}
		if u.FilesTotal != 0 {
			o.p("<div class=\"fig\"><span class=\"v\">%d</span><span class=\"k\">of %d files entered</span></div>\n",
				u.FilesEntered, u.FilesTotal)
		}
		if e.Count != 0 {
			o.p("<div class=\"fig\"><span class=\"v\">%.1f%%</span><span class=\"k\">of lines in those files</span></div>\n",
				100*float64(e.Covered)/float64(e.Count))
		}
		o.s(`</div>`)
		o.p("<p><b>The whole is considerably more than its largest part.</b> The single deepest "+
			"target reaches about 35%% on its own; all twenty-three together reach %.1f%%. The "+
			"other twenty-two therefore add roughly %s lines the deepest one never touches, which "+
			"is the case for keeping the narrow single-purpose harnesses rather than only the "+
			"broad ones.</p>\n",
			100*float64(l.Covered)/float64(maxI(l.Count, 1)), commaI(l.Covered-192769))
		if (f.Count > 0 || f.Covered > 0) && (b.Count > 0 || b.Covered > 0) {
			o.p("<div class=\"nb\">Functions reached (%.0f%%) sit well above branches taken (%.0f%%). "+
				"That gap is the shape of the remaining work: the campaign gets <i>into</i> about "+
				"half the functions but takes only about a third of the decisions inside them. What "+
				"is left is mostly error handling and edge conditions, not unexplored subsystems.</div>\n",
				100*float64(f.Covered)/float64(maxI(f.Count, 1)),
				100*float64(b.Covered)/float64(maxI(b.Count, 1)))
		}
	}

	var pending []string
	for _, t := range want {
		if _, ok := cov[t]; !ok {
			pending = append(pending, t)
		}
	}
	sort.Strings(pending)
	o.p("<p>Coverage is measured for <b>all %d targets</b>, one at a time. Each measurement replays "+
		"that target's whole corpus against a build compiled to record which lines execute.</p>\n", len(want))
	if len(pending) > 0 {
		var e []string
		for _, t := range pending {
			e = append(e, esc(t))
		}
		o.p("<div class=\"nb\"><b>Still being measured:</b> %s. "+
			"Listed here rather than omitted, so an absent figure cannot be mistaken for a measured "+
			"zero. This page is updated when it completes.</div>\n", strings.Join(e, ", "))
	}
	if len(covStale) > 0 && len(cov) == 0 {
		o.s(`<div class="nb">Coverage for this campaign has not been measured yet. Older figures exist ` +
			`but describe a different build and are not reported here.</div>`)
	}
	if len(cov) > 0 {
		o.s(`<div class="wrap"><table class="cells"><tr><th>Target</th><th>Lines covered</th>` +
			`<th>Lines it links</th><th>% of those</th><th>Functions</th><th>Branches</th></tr>`)
		var order []string
		for t := range cov {
			order = append(order, t)
		}
		// Name first, THEN a stable sort by coverage. Go's map iteration is
		// randomised, so ranking straight off it gives two targets with the
		// same percentage a different order on every render.
		sort.Strings(order)
		sort.SliceStable(order, func(i, j int) bool {
			pi, _ := pct(cov[order[i]].Lines.Covered, cov[order[i]].Lines.Count)
			pj, _ := pct(cov[order[j]].Lines.Covered, cov[order[j]].Lines.Count)
			return pi > pj
		})
		for _, t := range append(order, pending...) {
			c, ok := cov[t]
			if !ok {
				o.p("<tr><td class=\"t\">%s</td><td colspan=\"5\" style=\"text-align:left\" class=\"dim\">"+
					"measurement in progress</td></tr>\n", esc(shortName(t)))
				continue
			}
			ps := "&mdash;"
			if p, ok := pct(c.Lines.Covered, c.Lines.Count); ok {
				ps = fmtPct(p)
			}
			o.p("<tr><td class=\"t\">%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n",
				esc(shortName(t)), commaI(c.Lines.Covered), commaI(c.Lines.Count), ps,
				commaI(c.Functions.Covered), commaI(c.Branches.Covered))
		}
		o.s(`</table></div>`)

		// The deepest target with a fresh component breakdown.
		comps := DecodeComponents(d.Components)
		pick := ""
		for _, cand := range []string{"simple_query_fuzzer", "spi_query_fuzzer", "raw_parser_fuzzer"} {
			if r, ok := comps[cand]; ok && r.When >= CovValidFrom {
				pick = cand
				break
			}
		}
		if pick != "" {
			o.p("<h3>Where the coverage lands &mdash; %s</h3>\n", esc(pick))
			o.s(`<p>Broken down by component, so it is visible whether the vendor-patched code and the ` +
				`loaded extensions are being reached at all, rather than only core PostgreSQL.</p>`)
			row := comps[pick]
			comps := row.Components
			o.s(`<div class="wrap"><table class="cells"><tr><th>Component</th><th>Lines covered</th>` +
				`<th>Lines it links</th><th>% of those</th></tr>`)
			// The JSON's own key order, then a STABLE sort by coverage, so
			// components tied at the same count keep the order the coverage
			// tool emitted them in.
			ks := append([]string(nil), row.Order...)
			if len(ks) != len(comps) {
				for k := range comps {
					ks = append(ks, k)
				}
				sort.Strings(ks)
			}
			sort.SliceStable(ks, func(i, j int) bool {
				return comps[ks[i]].Lines.Covered > comps[ks[j]].Lines.Covered
			})
			for _, k := range ks {
				l := comps[k].Lines
				ps := "&mdash;"
				if p, ok := pct(l.Covered, l.Count); ok {
					ps = fmtPct(p)
				}
				o.p("<tr><td class=\"t\">%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n",
					esc(compLabel(k)), commaI(l.Covered), commaI(l.Count), ps)
			}
			o.s(`</table></div>`)
			if _, ok := comps["core (patched)"]; ok {
				o.s(`<div class="nb">&ldquo;core files the patch touches&rdquo; is every line of ` +
					`the 265 files the patch series modifies, not the patch itself. The patch adds ` +
					`26,073 lines into a 114,450-line universe &mdash; 22.8% &mdash; so the other ` +
					`three quarters is stock PostgreSQL that happens to share a file with a hunk, ` +
					`and the patch&rsquo;s own lines could be wholly covered or wholly missed ` +
					`without moving this figure much. It also sits above plain core partly ` +
					`because the patch touches tcop, the executor and the parser, which a query ` +
					`fuzzer exercises heavily whether or not they were patched.</div>`)
			}
		}
	}
	o.s(`</section>`)
}

func compLabel(k string) string {
	if v, ok := ComponentLabel[k]; ok {
		return v
	}
	return k
}

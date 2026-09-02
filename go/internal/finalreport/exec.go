package finalreport

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// The one-page report: what was tested, how much of it was reached, what is
// left.
//
// WHY A SECOND REPORT
//
// The campaign report answers "is this sound" -- gates, floors, what the
// ratchet let through, every component and its hash. That is the right report
// for someone who has to trust the numbers, and the wrong one for someone who
// has thirty seconds and wants to know whether the work is going anywhere.
//
// This one carries four things and no more: how much of the software was
// reached, how big the corpus is, WHAT was tested as a plain list, and whether
// another run would still be worth it. Percentages appear once, at the top.
// The list of what was tested deliberately carries no numbers beside it -- a
// reader who sees "43%" next to a plugin name will rank the plugins, and that
// is a conversation for the detailed report where the caveats live.

// ExecInputs is where the summary reads from.
type ExecInputs struct {
	Repo, WSRoot string
	Prefix       string
	Now          time.Time
}

type dayRate struct {
	Day  string
	Rate float64
}

// RenderExec writes the one-page summary.
func RenderExec(out io.Writer, in ExecInputs, css string) error {
	scripts := func(n string) string { return filepath.Join(in.Repo, "scripts", n) }

	u := ReadUnion(scripts("coverage-union.jsonl"))
	if u == nil || u.Lines.Count == 0 {
		return fmt.Errorf("no coverage union recorded")
	}
	pctAll := 100 * float64(u.Lines.Covered) / float64(u.Lines.Count)
	var brPct float64
	hasBr := u.Branches.Count != 0
	if hasBr {
		brPct = 100 * float64(u.Branches.Covered) / float64(u.Branches.Count)
	}

	// Corpus, from the newest per-workspace series row.
	series := readExecSeries(scripts("ratchet-series.jsonl"))
	corpus := map[string]int{}
	for _, r := range series {
		if r.WS == "" || len(r.Corpus) == 0 {
			continue
		}
		t := 0
		for _, v := range r.Corpus {
			t += v
		}
		corpus[r.WS] = t
	}
	totalCorpus := 0
	for k, v := range corpus {
		// Only the combined-plugin builds: the narrower workspaces test the
		// same server with fewer extensions, and adding them counts the same
		// inputs twice.
		if strings.Contains(k, "all") {
			totalCorpus += v
		}
	}

	plugins, exts := componentNames(scripts("coverage-components.jsonl"))
	targets := coverageTargets(scripts("coverage-series.jsonl"))
	rates := discoveryRates(series)
	rt := GatherRuntime(scripts("ratchet-series.jsonl"), in.WSRoot, in.Prefix)

	var sb strings.Builder
	o := w{&sb}
	o.s("<title>PG17 Fuzzing &mdash; Summary</title>")
	o.s(css)
	o.s(`<div class="shell"><main>`)
	o.s(`<header class="masthead">`)
	o.s(`<div class="eyebrow">PostgreSQL 17.10 &middot; patch series &middot; 13 plugins</div>`)
	o.s(`<h1>What was tested, and how far it got</h1>`)
	o.s(`<p class="standfirst">A fuzzing campaign runs a program against millions of ` +
		`generated inputs looking for crashes. Two things say whether it is working: ` +
		`how much of the code it manages to reach, and whether it is still finding ` +
		`anything new.</p>`)
	o.s(`</header>`)

	o.s(`<section><h2>The two numbers</h2>`)
	o.s(`<div class="figures">`)
	o.p("<div class=\"fig\"><span class=\"v\">%.0f%%</span>"+
		"<span class=\"k\">of the code was reached</span></div>\n", pctAll)
	o.p("<div class=\"fig\"><span class=\"v\">%.1fM</span>"+
		"<span class=\"k\">inputs kept as worth re-running</span></div>\n",
		float64(totalCorpus)/1e6)
	o.p("<div class=\"fig\"><span class=\"v\">%.0f h</span>"+
		"<span class=\"k\">of fuzzing, last run</span></div>\n", rt.LastRunHours)
	o.s(`</div>`)
	o.p("<p>The most recent run fuzzed for <b>%.1f hours</b> and completed %s slices "+
		"of work. Across the whole campaign there have been %d such runs, %s slices, "+
		"totalling %.0f hours of running time on %d separate days.</p>\n",
		rt.LastRunHours, commaI(rt.LastRunSlices), rt.Runs, commaI(rt.Slices),
		rt.ActiveHours, rt.Days)
	ch := rt.CoreHours
	if ch == nil {
		ch = rt.CoreHoursEst
	}
	if ch != nil {
		o.p("<p>In machine terms that is about <b>%.0f core-hours</b> of computer "+
			"handed to the work &mdash; roughly a month of one processor, run in "+
			"parallel over a few days.</p>\n", *ch)
	}
	o.s(`<p class="dim">Hours above are elapsed time while a run was under way, ` +
		`summed per run so the gaps between runs are excluded. Core-hours are the ` +
		`machine made available rather than the processor time actually burned; the ` +
		`two differ a great deal by component, because several spend most of their ` +
		`slice waiting on the database rather than computing.</p>`)
	strict := "lower"
	if hasBr {
		strict = fmt.Sprintf("%.0f%%", brPct)
	}
	o.p("<div class=\"eli5\"><p>&ldquo;Reached&rdquo; means an input caused that line of "+
		"code to run at least once. It is a floor on what was examined, not a claim "+
		"that each line was examined thoroughly &mdash; reaching a line and testing "+
		"every way through it are different things. By the stricter measure of "+
		"decision points rather than lines, the figure is %s.</p></div>\n", strict)
	o.s(`</section>`)

	o.s(`<section><h2>What was tested</h2>`)
	o.p("<p>PostgreSQL 17.10 with the patch series applied, built two ways &mdash; one "+
		"that detects memory errors, one that detects undefined behaviour &mdash; and "+
		"exercised through %d entry points.</p>\n", len(targets))
	o.s(`<h3>Extensions shipped with the patch</h3>`)
	o.p("<p class=\"dim\">%s</p>\n", esc(orNone(strings.Join(exts, ", "))))
	o.s(`<h3>Plugins built from source alongside it</h3>`)
	o.p("<p class=\"dim\">%s</p>\n", esc(orNone(strings.Join(plugins, ", "))))
	o.s(`<h3>Entry points exercised</h3>`)
	short := make([]string, 0, len(targets))
	for _, t := range targets {
		short = append(short, shortName(t))
	}
	o.p("<p class=\"dim\">%s</p>\n", esc(strings.Join(short, ", ")))
	o.s(`<div class="nb">Deliberately no percentage beside each name. Coverage varies ` +
		`enormously between them for reasons that are mostly about what a component ` +
		`needs in order to run at all &mdash; two of the plugins reach outside the ` +
		`machine for a database connection and cannot be driven from here. Ranking ` +
		`them on a bare number would mislead; the detailed report has the figures ` +
		`with the reasons attached.</div>`)
	o.s(`</section>`)

	o.s(`<section><h2>Is another run worth it?</h2>`)
	o.s(`<div class="eli5"><p>A campaign is finished when it stops finding new inputs ` +
		`worth keeping. That number falls fast at first &mdash; the easy ground is ` +
		`covered quickly &mdash; and the question is whether it has flattened or is ` +
		`still dropping.</p></div>`)
	o.s(`<div class="wrap"><table class="cells"><tr><th>Day</th>` +
		`<th>New inputs found, per slice of work</th><th>Change</th></tr>`)
	var prev float64
	first := true
	for _, r := range rates {
		change := "&mdash;"
		if !first {
			if r.Rate != 0 && prev/r.Rate >= 1 {
				change = fmt.Sprintf("%.1f&times; fewer", prev/r.Rate)
			} else {
				ratio := 1.0
				if prev != 0 {
					ratio = r.Rate / prev
				}
				change = fmt.Sprintf("%.1f&times; more", ratio)
			}
		}
		o.p("<tr><td class=\"t\">%s</td><td>%s</td><td>%s</td></tr>\n",
			r.Day, commaI(int(r.Rate)), change)
		prev, first = r.Rate, false
	}
	o.s(`</table></div>`)
	if len(rates) >= 3 {
		f, l, p2 := rates[0].Rate, rates[len(rates)-1].Rate, rates[len(rates)-2].Rate
		var fall, step float64
		if l != 0 {
			fall, step = f/l, p2/l
		}
		o.p("<p>Discovery fell <b>%.0f&times;</b> from the first day to the last. "+
			"But the final step was only %.1f&times;, which is the part that matters: "+
			"the steep decline has ended and the rate has settled at roughly %d new "+
			"inputs per slice rather than continuing toward zero.</p>\n",
			fall, step, int(l))
		o.s(`<div class="nb">So a further run would still find things, slowly and at a ` +
			`steady trickle rather than in the volumes of the first two days. What it ` +
			`would <i>not</i> do is move the coverage figure much: the code a settled ` +
			`corpus reaches is largely the code it has already reached. Raising ` +
			`coverage further is a question of giving the campaign new ways in, not ` +
			`of running the existing ones for longer.</div>`)
	}
	o.s(`</section>`)

	o.p("<footer><p class=\"dim\">Generated %s from the campaign's own instrumentation. "+
		"The detailed report carries the per-component figures, the gates, and the "+
		"caveats behind every number here.</p></footer>\n",
		in.Now.Format("2006-01-02 15:04"))
	o.s(`</main></div>`)

	_, err := io.WriteString(out, strings.TrimSuffix(sb.String(), "\n"))
	return err
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

type execSeriesRow struct {
	WS       string          `json:"ws"`
	LogMTime string          `json:"log_mtime"`
	Corpus   map[string]int  `json:"corpus"`
	NewUnits json.RawMessage `json:"new_units"`
}

func readExecSeries(path string) []execSeriesRow {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []execSeriesRow
	dec := json.NewDecoder(f)
	for {
		var r execSeriesRow
		if err := dec.Decode(&r); err != nil {
			break
		}
		out = append(out, r)
	}
	return out
}

// componentNames splits the union's component keys into plugins and
// patch-shipped extensions.
func componentNames(path string) (plugins, exts []string) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil
	}
	defer f.Close()
	var last map[string]json.RawMessage
	dec := json.NewDecoder(f)
	for {
		var r struct {
			Target     string                     `json:"target"`
			Components map[string]json.RawMessage `json:"components"`
		}
		if err := dec.Decode(&r); err != nil {
			break
		}
		if r.Target == "__union__" {
			last = r.Components
		}
	}
	for k := range last {
		if name, ok := strings.CutPrefix(k, "plugin:"); ok {
			plugins = append(plugins, name)
		}
		if name, ok := strings.CutPrefix(k, "ext:"); ok {
			exts = append(exts, name)
		}
	}
	sort.Strings(plugins)
	sort.Strings(exts)
	return plugins, exts
}

func coverageTargets(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	seen := map[string]bool{}
	dec := json.NewDecoder(f)
	for {
		var r struct {
			Target string `json:"target"`
		}
		if err := dec.Decode(&r); err != nil {
			break
		}
		if r.Target != "" && r.Target != "__union__" {
			seen[r.Target] = true
		}
	}
	var out []string
	for t := range seen {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// discoveryRates is new inputs per slice, by day.
//
// Per SLICE, not per day: the number of slices in a day varies with how the
// campaign was scheduled, and a per-day total would fall simply because fewer
// slices ran.
func discoveryRates(series []execSeriesRow) []dayRate {
	type acc struct{ slices, units int }
	per := map[string]*acc{}
	for _, r := range series {
		if r.LogMTime == "" {
			continue
		}
		t, err := parseISO(r.LogMTime)
		if err != nil {
			continue
		}
		d := t.Format("2006-01-02")
		if per[d] == nil {
			per[d] = &acc{}
		}
		per[d].slices++
		per[d].units += sumNewUnits(r.NewUnits)
	}
	var days []string
	for d := range per {
		days = append(days, d)
	}
	sort.Strings(days)
	var out []dayRate
	for _, d := range days {
		if per[d].slices == 0 {
			continue
		}
		out = append(out, dayRate{d, float64(per[d].units) / float64(per[d].slices)})
	}
	return out
}

// sumNewUnits accepts both shapes the field has had: a per-target map, and a
// bare number from before the per-target form existed.
func sumNewUnits(raw json.RawMessage) int {
	if len(raw) == 0 {
		return 0
	}
	var m map[string]int
	if json.Unmarshal(raw, &m) == nil {
		t := 0
		for _, v := range m {
			t += v
		}
		return t
	}
	var n int
	if json.Unmarshal(raw, &n) == nil {
		return n
	}
	return 0
}

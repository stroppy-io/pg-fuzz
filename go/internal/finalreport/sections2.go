package finalreport

import (
	"encoding/json"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

func renderFindings(o w, d Data, wsd map[string]WorkspaceData) {
	fnd := d.Findings
	totArt := 0
	for _, ws := range wsd {
		for _, tt := range ws.Targets {
			for _, v := range tt.Artifacts {
				totArt += v
			}
		}
	}
	o.s(`<section id="findings"><h2>Findings on record</h2>`)
	o.s(`<div class="eli5"><p>Two different numbers get called &ldquo;findings&rdquo;, and ` +
		`confusing them overstates the result by more than tenfold.</p>` +
		`<p>An <b>artifact</b> is one saved input that made the target crash, run out of ` +
		`memory, or hang. The fuzzer writes one file <i>every time</i> it happens, so a ` +
		`single underlying defect hit repeatedly produces hundreds of them.</p>` +
		`<p>A <b>finding</b> is a distinct defect after triage &mdash; after those artifacts ` +
		`have been reduced, grouped by signature, and confirmed. That is the number that ` +
		`means something.</p></div>`)
	o.s(`<div class="figures">`)
	o.p("<div class=\"fig\"><span class=\"v\">%s</span><span class=\"k\">raw artifacts</span></div>\n", commaI(totArt))
	o.p("<div class=\"fig\"><span class=\"v\">%s</span><span class=\"k\">distinct findings, triaged</span></div>\n",
		commaI(fnd.Total))
	o.s(`</div>`)
	// THE TWO FIGURES ABOVE ARE NOT THE SAME SCOPE, and side by side they read
	// as though they were. The artifact count is this run's, taken from its
	// own workspaces. The finding count is the project's whole FINDINGS
	// directory, which this report scans in full and prints under a heading
	// naming one campaign -- so a run that built no storage engine published
	// eight storage-engine findings whose own write-ups name workspaces from
	// other campaigns entirely.
	//
	// Nothing in a write-up records the campaign that produced it, so the
	// numbers cannot be filtered here. The page stops claiming instead.
	o.s(`<div class="eli5"><p><b>These are the project's standing findings, not ` +
		`this run's alone.</b> A finding is a write-up a person made after triage, and ` +
		`write-ups are not stamped with the campaign that produced them &mdash; so they ` +
		`cannot be attributed to one run, and this page does not pretend otherwise. ` +
		`What <i>this</i> run produced is the artifact count beside it.</p></div>`)
	if len(fnd.ByCategory) > 0 {
		o.s(`<p>By area of the system:</p>`)
		o.s(`<div class="wrap"><table class="cells"><tr><th>Area</th><th>Distinct findings</th></tr>`)
		for _, k := range sortedByCountThenKey(fnd.ByCategory) {
			o.p("<tr><td class=\"t\">%s</td><td>%s</td></tr>\n", esc(k), commaI(fnd.ByCategory[k]))
		}
		o.s(`</table></div>`)
	}
	if len(fnd.ByTarget) > 0 {
		o.s(`<h3>Which fuzzer found them</h3>`)
		o.s(`<p>A finding is attributed to a target when the write-up says so outright, or ` +
			`when it names exactly one. A write-up naming several is left unattributed on ` +
			`purpose: those are systemic &mdash; a deadline that never fires, a budget eaten ` +
			`by replay &mdash; and hit many targets at once. Pinning one on whichever fuzzer ` +
			`is mentioned first would invent a precision the evidence does not have.</p>`)
		o.s(`<div class="wrap"><table class="cells"><tr><th>Target</th><th>Distinct findings</th></tr>`)
		for _, k := range sortedByCountThenKey(fnd.ByTarget) {
			o.p("<tr><td class=\"t\">%s</td><td>%s</td></tr>\n", esc(shortName(k)), commaI(fnd.ByTarget[k]))
		}
		for _, p := range []struct {
			Label string
			N     int
		}{
			{"systemic &mdash; several targets at once", fnd.Systemic},
			{"found by a different harness", fnd.Other},
			{"not attributable from the write-up", fnd.Unattr},
		} {
			if p.N != 0 {
				o.p("<tr><td class=\"dim\">%s</td><td>%s</td></tr>\n", p.Label, commaI(p.N))
			}
		}
		o.s(`</table></div>`)
	}
	o.s(`<div class="nb">Counts only, deliberately. Which component carries which defect, and ` +
		`whether it is reported upstream, is the maintainers&rsquo; call to make and not this ` +
		`report&rsquo;s to pre-empt. The per-target table above shows raw artifact counts so the ` +
		`shape of the run is visible; the artifacts and reproducers are not published here.</div>`)
	o.s(`<p>The per-target artifact counts are worth reading as a <i>map of where the run spent ` +
		`its luck</i>, not as a scoreboard. Two targets account for most of the raw total, and in ` +
		`both cases that is one signature hit over and over rather than many separate problems.</p>`)
	o.s(`</section>`)
}

// sortedByCountThenKey orders a count map descending, breaking ties on the
// NAME.
//
// Alphabetical is not an arbitrary choice here -- it is what the published
// report already does. The gather writes its JSON with sorted keys, so the
// renderer read the categories back in alphabetical order and its stable sort
// preserved that. Relying on the order a map happens to yield is what made
// this table reorder itself between renders of identical data; Python's
// dictionaries hid that by preserving insertion order, and Go's do not.
func sortedByCountThenKey(m map[string]int) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.SliceStable(ks, func(i, j int) bool {
		if m[ks[i]] != m[ks[j]] {
			return m[ks[i]] > m[ks[j]]
		}
		return ks[i] < ks[j]
	})
	return ks
}

type invComponent struct {
	Layer         string `json:"layer"`
	Name          string `json:"name"`
	Kind          string `json:"kind"`
	Hash          string `json:"hash"`
	Detail        string `json:"detail"`
	InFingerprint *bool  `json:"in_fingerprint"`
}

func renderInventory(o w, d Data) {
	var inv struct {
		Components []invComponent `json:"components"`
		Unreadable int            `json:"unreadable"`
	}
	if len(d.Inventory) > 0 {
		_ = json.Unmarshal(d.Inventory, &inv)
	}
	rows := inv.Components
	if len(rows) == 0 {
		return
	}
	o.s(`<section id="components"><h2>Every component, and its hash</h2>`)
	o.s(`<div class="eli5"><p>The fingerprint is eight characters. It answers ` +
		`"are these two runs the same" and nothing else &mdash; when it changes it ` +
		`does not say what changed, and two years from now it is not a build ` +
		`recipe. This is the expansion: every input, layer by layer, with the hash ` +
		`that identifies it.</p>` +
		`<p>A dot marks something recorded but deliberately <i>not</i> hashed into ` +
		`the fingerprint &mdash; the driver script, the build recipe. They shape ` +
		`the build without defining the experiment, and marking them keeps the ` +
		`difference visible instead of implied.</p></div>`)
	layers := map[string]bool{}
	for _, r := range rows {
		layers[r.Layer] = true
	}
	o.s(`<div class="figures">`)
	o.p("<div class=\"fig\"><span class=\"v\">%d</span><span class=\"k\">components</span></div>\n", len(rows))
	o.p("<div class=\"fig\"><span class=\"v\">%d</span><span class=\"k\">layers</span></div>\n", len(layers))
	o.p("<div class=\"fig\"><span class=\"v\">%d</span><span class=\"k\">unreadable</span></div>\n", inv.Unreadable)
	o.s(`</div>`)
	if inv.Unreadable != 0 {
		o.p("<div class=\"nb\">%d component(s) could not be hashed. They are listed "+
			"as UNREADABLE rather than skipped &mdash; a component list with a "+
			"quiet hole looks complete, which is worse than one that admits "+
			"it.</div>\n", inv.Unreadable)
	}
	cur := ""
	first := true
	for _, r := range rows {
		if r.Layer != cur {
			if !first {
				o.s(`</table></div>`)
			}
			first = false
			cur = r.Layer
			o.p("<h3>%s</h3>\n", esc(cur))
			o.s(`<div class="wrap"><table class="cells"><tr><th>Component</th>` +
				`<th>Kind</th><th>Hash</th><th>Note</th></tr>`)
		}
		fp := ""
		if r.InFingerprint != nil && !*r.InFingerprint {
			fp = ` <span class="dim" title="not hashed into the fingerprint">&middot;</span>`
		}
		hc := ""
		if r.Hash == "UNREADABLE" {
			hc = ` class="dim"`
		}
		o.p("<tr><td class=\"t\">%s%s</td><td>%s</td><td%s><code>%s</code></td>"+
			"<td style=\"text-align:left\">%s</td></tr>\n",
			esc(r.Name), fp, esc(r.Kind), hc, esc(r.Hash), esc(r.Detail))
	}
	o.s(`</table></div>`)
	o.s(`</section>`)
}

func renderMasked(o w, mk Masked) {
	acks, degr, rskip := mk.Acks, mk.Degraded, mk.RegimeSkipped
	o.s(`<section id="masked"><h2>What the gates did not fail on</h2>`)
	o.s(`<div class="eli5"><p>A ratchet earns its keep by not crying wolf, and every ` +
		`rule that stops it crying wolf also hides something. A report that shows only ` +
		`what passed inherits that blindness, so this section lists what was let ` +
		`through and why.</p>` +
		`<p>Three ways it happens. An <b>acknowledgement</b> suppresses a target ` +
		`outright &mdash; a decision made deliberately in a commit, but one nobody ` +
		`revisits becomes a finding nobody looked at. The <b>tolerance</b> is "at least ` +
		`a tenth of the record", not "within a tenth of it", so a target can fall by ` +
		`eighty per cent and still pass. And a floor earned under a different ` +
		`configuration is <b>skipped as not comparable</b>, which is correct and still ` +
		`leaves that target unguarded.</p></div>`)
	o.s(`<div class="figures">`)
	o.p("<div class=\"fig\"><span class=\"v\">%d</span><span class=\"k\">acknowledged</span></div>\n", len(acks))
	o.p("<div class=\"fig\"><span class=\"v\">%d</span><span class=\"k\">passing under half their floor</span></div>\n", len(degr))
	o.p("<div class=\"fig\"><span class=\"v\">%d</span><span class=\"k\">floors unenforced (regime)</span></div>\n", len(rskip))
	o.s(`</div>`)

	if len(acks) > 0 {
		o.s(`<h3>Acknowledged, and therefore silent</h3>`)
		o.s(`<div class="wrap"><table class="cells"><tr><th>Target</th><th>Reason</th>` +
			`<th>Since</th><th>Age</th></tr>`)
		old := false
		for _, a := range acks {
			aged, ageS := "", "&mdash;"
			if a.AgeDays == nil {
				aged = ` class="dim"`
			} else {
				ageS = strconv.Itoa(*a.AgeDays) + " days"
				if *a.AgeDays > 30 {
					old = true
				}
			}
			o.p("<tr><td class=\"t\">%s</td><td style=\"text-align:left\">%s</td><td>%s</td><td%s>%s</td></tr>\n",
				esc(a.Target), esc(a.Reason), esc(a.Since), aged, ageS)
		}
		o.s(`</table></div>`)
		if old {
			o.s(`<div class="nb">An acknowledgement older than a month is worth re-reading. ` +
				`It was a judgement about a target at a moment; both may have moved.</div>`)
		}
	} else {
		o.s(`<p>No targets are currently acknowledged, so nothing is suppressed outright.</p>`)
	}

	if len(degr) > 0 {
		o.s(`<h3>Passing, a long way below their own record</h3>`)
		o.s(`<p>These clear the bar and sit under half of what they once managed. ` +
			`Nothing fails here, which is the point of showing it &mdash; the lowest rows ` +
			`are within a hair of the threshold.</p>`)
		o.s(`<div class="wrap"><table class="cells"><tr><th>Target</th><th>Build</th>` +
			`<th>Observed</th><th>Floor</th><th>Fraction</th></tr>`)
		for i, x := range degr {
			if i >= 20 {
				break
			}
			build := x.WS
			if i := strings.LastIndex(build, "-"); i >= 0 {
				build = build[i+1:]
			}
			o.p("<tr><td class=\"t\">%s</td><td>%s</td><td>%s</td><td>%s</td><td>%.2f&times;</td></tr>\n",
				esc(shortName(x.Target)), esc(build), commaI(x.Observed), commaI(x.Floor), x.Ratio)
		}
		o.s(`</table></div>`)
		if len(degr) > 20 {
			o.p("<p class=\"dim\">%d more not listed.</p>\n", len(degr)-20)
		}
	}

	if len(rskip) > 0 {
		o.s(`<h3>Floors not currently enforced</h3>`)
		o.s(`<p>Earned under a different job count, so not comparable to what runs now. ` +
			`They will be re-established, and until then these targets have no floor ` +
			`guarding them.</p>`)
		seen := map[string]bool{}
		var names []string
		for _, x := range rskip {
			n := shortName(x.Target)
			if !seen[n] {
				seen[n] = true
				names = append(names, n)
			}
		}
		sort.Strings(names)
		o.p("<p class=\"dim\">%s</p>\n", esc(strings.Join(names, ", ")))
	}
	o.s(`</section>`)
}

func renderRatchet(o w, in RenderInputs, targets []string, nFloors int) {
	o.s(`<section id="ratchet"><h2>The ratchet</h2>`)
	o.s(`<div class="eli5"><p>A <b>ratchet</b> records the best each target has ever done and fails the ` +
		`run if it later does meaningfully worse. It exists because the dangerous failure in fuzzing is ` +
		`silent: a target that stops working still produces logs, still writes files, and still looks ` +
		`healthy. Only comparison against its own past catches it.</p>` +
		`<p>An <b>exec floor</b> is the number of inputs a target has run before. A <b>rate floor</b> is ` +
		`how fast it ran them. Rate matters separately &mdash; a target given twice the time can clear ` +
		`its exec floor while running at half speed, and the ratchet should notice.</p></div>`)
	nRate := 0
	for _, v := range in.RateFloors {
		nRate += len(v)
	}
	o.s(`<div class="figures">`)
	o.p("<div class=\"fig\"><span class=\"v\">%s</span><span class=\"k\">exec floors recorded</span></div>\n", commaI(nFloors))
	o.p("<div class=\"fig\"><span class=\"v\">%d</span><span class=\"k\">workspaces covered</span></div>\n", len(in.Floors))
	o.p("<div class=\"fig\"><span class=\"v\">%d</span><span class=\"k\">rate floors</span></div>\n", nRate)
	o.p("<div class=\"fig\"><span class=\"v\">%s</span><span class=\"k\">tolerance</span></div>\n",
		esc(trimFloat(in.Tolerance)))
	o.s(`</div>`)
	o.s(`<p>Floors for the two campaign builds, as they stood when the run stopped:</p>`)
	o.s(`<div class="wrap"><table class="cells"><tr><th>Target</th><th>ASan exec floor</th>` +
		`<th>ASan rate /s</th><th>UBSan exec floor</th><th>UBSan rate /s</th></tr>`)
	fa, fu := in.Floors[Builds[0][0]], in.Floors[Builds[1][0]]
	ra, ru := in.RateFloors[Builds[0][0]], in.RateFloors[Builds[1][0]]
	for _, t := range targets {
		o.p("<tr><td class=\"t\">%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n",
			esc(shortName(t)), intOrDash(fa, t), rateOrDash(ra, t),
			intOrDash(fu, t), rateOrDash(ru, t))
	}
	o.s(`</table></div>`)
	if nRate == 0 {
		o.p("<div class=\"nb\"><b>The speed floors were reset after this run, on purpose.</b> They had "+
			"been recorded per-job while the execution counts beside them were per-target totals, so "+
			"the two were never comparable. Rather than keep numbers that could not fail, they were "+
			"discarded and will be re-established from the next run's measurements. The "+
			"%d execution-count floors below are unaffected and carry the campaign's full "+
			"history.</div>\n", nFloors)
	}
	o.s(`<div class="nb">Exec floors are cumulative across the campaign&rsquo;s history; the per-target ` +
		`&ldquo;execs&rdquo; figures in the table above are for the final slice only. They are different ` +
		`measurements and should not be compared directly.</div>`)
	o.s(`</section>`)
}

func intOrDash(m map[string]int, k string) string {
	if v, ok := m[k]; ok {
		return commaI(v)
	}
	return "&mdash;"
}

func rateOrDash(m map[string]float64, k string) string {
	if v, ok := m[k]; ok && v != 0 {
		return f0(v)
	}
	return "&mdash;"
}

// trimFloat renders the tolerance the way Python's str() did: 0.1, not 0.100000.
func trimFloat(f float64) string {
	if f == 0 {
		return "&mdash;"
	}
	return strconv.FormatFloat(f, 'g', -1, 64)
}

func renderPatches(o w, d Data) {
	o.s(`<section id="patches"><h2>Source changes</h2>`)
	o.s(`<div class="eli5"><p>Four different kinds of source change are in play, and the difference ` +
		`matters. A <b>patch series</b> is code we were given and are testing. A <b>cherry-pick</b> is ` +
		`an upstream fix pulled back. A <b>patched extension</b> is a local change to third-party code ` +
		`so it survives being fuzzed. <b>Harness</b> code is ours &mdash; the fuzz targets themselves.</p>` +
		`<p>Only a patched extension could be mistaken for &ldquo;we found a bug in someone else's ` +
		`software&rdquo;, and at least one of them is not that: it is a compatibility change so the ` +
		`extension tolerates being driven far harder than it was designed for.</p></div>`)
	kinds := map[string][]Patch{}
	for _, p := range d.Patches {
		k := p.Kind
		if k == "" {
			k = "other"
		}
		kinds[k] = append(kinds[k], p)
	}
	for _, kind := range []string{"core patch", "patched extension", "harness"} {
		ps, ok := kinds[kind]
		if !ok {
			continue
		}
		o.p("<h3>%s</h3>\n", esc(kind))
		o.s(`<div class="wrap"><table class="cells"><tr><th>What</th><th>Where</th></tr>`)
		for _, p := range ps {
			what := p.Name
			if what == "" {
				what = filepath.Base(p.Path)
			}
			extra := p.Head
			if extra == "" {
				extra = p.Note
			}
			o.p("<tr><td class=\"t\">%s</td><td>%s</td></tr>\n", esc(what), esc(p.Path))
			if extra != "" {
				o.p("<tr><td></td><td class=\"dim\">%s</td></tr>\n", esc(extra))
			}
		}
		o.s(`</table></div>`)
	}
	o.s(`<div class="nb">The extension change guards against a lock the extension could take twice ` +
		`against itself under the harness&rsquo;s call pattern. It is a harness-compatibility fix, not ` +
		`a defect report against that project.</div>`)
	o.s(`</section>`)
}

func renderLimits(o w) {
	o.s(`<section id="limits"><h2>Limits &amp; open items</h2>`)
	o.s(`<p>Stated plainly, because a report that only lists what worked is not much use:</p><ul>`)
	for _, li := range []string{
		`<li><b>Coverage is reproducible to within measurement noise.</b> Every target was ` +
			`measured twice &mdash; once one-at-a-time, once with all 23 running concurrently in ` +
			`isolated containers. Twenty of 23 agreed exactly; the other three differed by 3, 4 and ` +
			`34 lines out of tens of thousands. Two repeats of the <i>same</i> serial method differ ` +
			`by a similar amount, so that is the noise floor of the measurement, not a defect in it.</li>`,
		`<li><b>Coverage is a post-hoc snapshot.</b> It was measured after the run against the final ` +
			`corpus, not tracked continuously, so it shows where the corpus ended up rather than how it ` +
			`got there.</li>`,
		`<li><b>The coverage build had drifted &mdash; now checked automatically.</b> It was built two ` +
			`days before the fuzzing builds and, because its configuration named the unpatched version of ` +
			`one extension, a clean rebuild still produced different software. Coverage from it would have ` +
			`sat beside corpus figures describing a different program. A check now compares the source ` +
			`commit, every shared extension&rsquo;s version, and the applied patches across all three ` +
			`builds, and refuses to let them diverge silently.</li>`,
		`<li><b>Ten of the throughput floors were measured in the wrong unit.</b> A target runs ` +
			`several jobs at once. The execution counts were added together across those jobs, correctly, ` +
			`but so were their durations &mdash; and concurrent durations do not add. The resulting speed ` +
			`figure was per-job while the count beside it was the total, and comparing them implied up to ` +
			`88 hours of work for a two-hour slice. Fixed, and the affected floors were discarded rather ` +
			`than kept: a floor nothing can fail is worse than no floor. The execution-count floors are ` +
			`unaffected.</li>`,
		`<li><b>Per-target logs are per-slice.</b> Soak overwrites each target&rsquo;s log every slice, ` +
			`so the shipped logs hold the final slice, not the whole run. Cumulative history lives in the ` +
			`ratchet series, which is included.</li>`,
		`<li><b>Two targets needed restarting during the run.</b> Both drive a real server process and ` +
			`can wedge it; a watchdog restarts them. The underlying cause is understood for one path and ` +
			`not fully for the other.</li>`,
		`<li><b>An earlier corpus cap archived a large number of inputs</b> on a diagnosis that turned ` +
			`out to be wrong. They were archived rather than deleted and the counts are shown per target ` +
			`above.</li>`,
	} {
		o.s(li)
	}
	o.s(`</ul></section>`)
}

func renderBundle(o w) {
	o.s(`<section id="bundle"><h2>The bundle</h2>`)
	o.s(`<p>Shipped alongside this report:</p>`)
	o.s(`<div class="wrap"><table class="cells"><tr><th>File</th><th>Contents</th></tr>`)
	for _, f := range [][2]string{
		{"corpus-asan.tar.zst", "every input kept by the ASan build, per target"},
		{"corpus-ubsan.tar.zst", "every input kept by the UBSan build, per target"},
		{"fuzzing-logs.tar.gz", "per-target fuzzer logs (final slice)"},
		{"ratchet-baseline.json", "all exec and rate floors"},
		{"ratchet-series.jsonl", "per-slice history for every target"},
		{"coverage-series.jsonl", "coverage totals per target"},
		{"coverage-components.jsonl", "coverage split by component"},
		{"final-report-data.json", "the data this report is rendered from"},
		{"campaign-stopped.marker", "corpus snapshot at the moment of stop"},
	} {
		o.p("<tr><td class=\"t\">%s</td><td>%s</td></tr>\n", esc(f[0]), esc(f[1]))
	}
	o.s(`</table></div></section>`)
}

func fmtPct(p float64) string { return strconv.FormatFloat(p, 'f', 2, 64) + "%" }

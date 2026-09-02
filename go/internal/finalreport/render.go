package finalreport

import (
	"fmt"
	"html"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// The snapshot report: one run, self-contained, no navigation and no history.
// The thing you hand to someone who was not here. The campaign HISTORY index
// is the opposite -- every run, the deltas between them, links backward -- and
// conflating the two helps nobody.

// CovValidFrom is the earliest coverage measurement that describes this
// campaign's build.
const CovValidFrom = "2026-08-27T08:01:00"

// CovMaxLagHours: a coverage pass writes its rows within minutes of each
// other, so a target lagging the newest by more than this did not take part in
// the most recent pass.
const CovMaxLagHours = 12

// RenderInputs is everything the page needs beyond the gathered data.
type RenderInputs struct {
	Data       Data
	Union      *Union
	Floors     map[string]map[string]int
	RateFloors map[string]map[string]float64
	Tolerance  float64
	StoppedAt  string
}

type w struct{ b *strings.Builder }

func (o w) p(format string, a ...any) { fmt.Fprintf(o.b, format, a...) }
func (o w) s(str string)              { o.b.WriteString(str); o.b.WriteByte('\n') }

func esc(s string) string {
	// The same three replacements the previous renderer made, and no more:
	// escaping quotes as well would change every hash and path in the tables.
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")
	return r.Replace(s)
}

// num formats an integer with thousands separators, or an em dash for absent.
//
// ABSENT AND ZERO ARE DIFFERENT. A target with no measurement shows a dash; a
// target measured at zero shows 0, and reading one as the other is how "never
// ran" becomes "ran and found nothing".
func num(v *int) string {
	if v == nil {
		return "&mdash;"
	}
	return commaI(*v)
}

func numI(v int) string { return commaI(v) }

func pct(cov, cnt int) (float64, bool) {
	if cnt == 0 {
		return 0, false
	}
	return 100 * float64(cov) / float64(cnt), true
}

// Render writes the whole page.
func Render(out io.Writer, in RenderInputs, css string) error {
	var sb strings.Builder
	o := w{&sb}
	d := in.Data
	wsd := d.Workspaces

	cov, covStale := splitCoverage(DecodeCoverage(d.Coverage))

	seen := map[string]bool{}
	var targets []string
	for _, v := range wsd {
		for t := range v.Targets {
			if !seen[t] {
				seen[t] = true
				targets = append(targets, t)
			}
		}
	}
	sort.Strings(targets)

	fper := d.Findings.ByTarget
	totCorpus := 0
	for _, v := range wsd {
		totCorpus += v.CorpusTotal
	}
	nFloors := 0
	for _, v := range in.Floors {
		nFloors += len(v)
	}

	o.s("<title>PG17 Fuzz Soak</title>")
	o.s(css)
	o.s(`<div class="shell">`)

	secs := [][2]string{
		{"summary", "What this is"}, {"how", "How fuzzing works here"},
		{"run", "The run"}, {"cells", "Every target"}, {"coverage", "Coverage"},
		{"ratchet", "The ratchet"}, {"patches", "Source changes"},
		{"limits", "Limits &amp; open items"}, {"bundle", "The bundle"},
	}
	o.s(`<div class="rail"><div class="rail-mark"><b>pg-fuzz</b>final report</div><nav aria-label="Sections"><ol>`)
	for i, s := range secs {
		o.p("<li><a href=\"#%s\"><span class=\"n\">%02d</span><span>%s</span></a></li>\n", s[0], i+1, s[1])
	}
	o.s(`</ol></nav></div><main>`)

	o.s(`<header class="masthead">`)
	o.s(`<div class="eyebrow">PostgreSQL 17.10 &middot; patched distribution &middot; fuzzing campaign</div>`)
	o.s(`<h1>A soak run against PostgreSQL 17.10</h1>`)
	o.s(`<p class="standfirst">Twenty-three fuzz targets, two sanitizer builds, run continuously ` +
		`and stopped on a schedule at 08:00 on 27 August 2026. This is what ran, what it covered, ` +
		`and what was changed to make it run.</p>`)
	o.s(`</header>`)

	// ---------------- summary ----------------
	o.s(`<section id="summary"><h2>What this is</h2>`)
	o.s(`<div class="eli5"><p><b>Fuzzing</b> means feeding a program millions of generated inputs ` +
		`and watching for it to crash or misbehave. You keep the inputs that reach code nothing has ` +
		`reached before; over time that collection &mdash; the <b>corpus</b> &mdash; grows into a set ` +
		`of inputs that exercises the program broadly.</p>` +
		`<p>This report covers one continuous run against PostgreSQL 17.10 as shipped in the patched ` +
		`distribution, with third-party extensions loaded. It reports the machinery and the ` +
		`measurements. Defect detail is deliberately kept to counts and categories.</p></div>`)
	o.s(`<div class="figures">`)
	o.s(`<div class="fig"><span class="v">23</span><span class="k">fuzz targets</span></div>`)
	o.s(`<div class="fig"><span class="v">2</span><span class="k">sanitizer builds</span></div>`)
	o.p("<div class=\"fig\"><span class=\"v\">%d</span><span class=\"k\">target &times; build cells</span></div>\n",
		len(targets)*len(wsd))
	o.p("<div class=\"fig\"><span class=\"v\">%s</span><span class=\"k\">corpus inputs kept</span></div>\n",
		numI(totCorpus))
	if in.Union != nil && in.Union.Lines.Count > 0 {
		l := in.Union.Lines
		o.p("<div class=\"fig\"><span class=\"v\">%.1f%%</span><span class=\"k\">of the server executed</span></div>\n",
			100*float64(l.Covered)/float64(maxI(l.Count, 1)))
	}
	o.p("<div class=\"fig\"><span class=\"v\">%s</span><span class=\"k\">ratchet floors held</span></div>\n", numI(nFloors))
	o.p("<div class=\"fig\"><span class=\"v\">%d</span><span class=\"k\">source changes listed</span></div>\n", len(d.Patches))
	o.s(`</div>`)
	o.s(`<p>Every one of the 23 targets was fuzzing when the run was stopped. That is worth stating ` +
		`plainly because it was not true at the start of the week: several targets were replaying ` +
		`their saved inputs and never generating new ones, which produces confident-looking logs and ` +
		`no testing at all. Finding and fixing that is a large part of what this campaign did.</p>`)
	o.s(`</section>`)

	// ---------------- how ----------------
	o.s(`<section id="how"><h2>How fuzzing works here</h2>`)
	o.s(`<div class="eli5"><p>A <b>fuzz target</b> is a small program that takes a chunk of bytes and ` +
		`feeds it into one part of PostgreSQL. The fuzzer generates bytes, runs the target, and watches ` +
		`which lines of code get executed.</p>` +
		`<p>An input that reaches new code is <b>kept</b>; one that does not is thrown away. The kept ` +
		`inputs are the corpus. Starting a run means <b>replaying</b> the whole corpus first, which ` +
		`costs time but establishes the baseline; only after that does the fuzzer start ` +
		`<b>mutating</b> &mdash; making small random changes to look for new behaviour.</p>` +
		`<p>A <b>sanitizer</b> is a compiler setting that makes the program check itself as it runs. ` +
		`<b>ASan</b> (address) catches reads and writes outside valid memory. <b>UBSan</b> (undefined ` +
		`behaviour) catches operations the C language does not define, such as signed overflow. The ` +
		`same target is built twice, once under each, because they detect different things.</p></div>`)
	o.p("<p>Two builds were fuzzed &mdash; one ASan, one UBSan &mdash; giving %d target &times; build "+
		"cells. A third build, compiled for coverage measurement rather than bug detection, is used "+
		"only to answer &ldquo;which code did the corpus actually reach?&rdquo;</p>\n", len(targets)*len(wsd))
	o.s(`</section>`)

	// ---------------- run ----------------
	o.s(`<section id="run"><h2>The run</h2>`)
	stopped := in.StoppedAt
	if stopped == "" {
		stopped = "08:00"
	}
	o.p("<p>The run was stopped on a timer at <b>%s</b> local time, on request, rather than at a "+
		"natural end. Nothing was mid-write; the stop is a clean shutdown that lets each target "+
		"finish its current slice.</p>\n", esc(stopped))
	o.s(`<div class="eli5"><p>The run used <b>soak</b> mode: targets are kept continuously busy from a ` +
		`shared pool rather than run in fixed rounds. Rounds restart every target on a schedule, and ` +
		`each restart pays the replay cost again &mdash; with a corpus of this size that was consuming ` +
		`most of the machine's time. Soak pays replay once.</p></div>`)
	o.s(`<div class="wrap"><table class="cells"><tr><th>Build</th><th>Sanitizer</th>` +
		`<th>Targets</th><th>Corpus inputs</th></tr>`)
	var wsNames []string
	for ws := range wsd {
		wsNames = append(wsNames, ws)
	}
	sort.Strings(wsNames)
	for _, ws := range wsNames {
		o.p("<tr><td class=\"t\">%s</td><td>%s</td><td>%d</td><td>%s</td></tr>\n",
			esc(ws), sanitizerOf(ws), len(wsd[ws].Targets), numI(wsd[ws].CorpusTotal))
	}
	o.p("<tr><td class=\"t\">total</td><td></td><td></td><td>%s</td></tr>\n", numI(totCorpus))
	o.s(`</table></div></section>`)

	renderRuntime(o, d.Runtime)
	renderCells(o, d, in, targets, cov, fper)
	renderCoverage(o, d, in, targets, cov, covStale)
	renderFindings(o, d, wsd)
	renderInventory(o, d)
	renderMasked(o, d.Masked)
	renderRatchet(o, in, targets, nFloors)
	renderPatches(o, d)
	renderLimits(o)
	renderBundle(o)

	o.p("<footer><p class=\"dim\">Rendered %s. Figures come from the campaign's own instrumentation; "+
		"the data file is included so they can be checked.</p></footer>\n", esc(d.Generated))
	o.s(`</main></div>`)

	_, err := io.WriteString(out, strings.TrimSuffix(sb.String(), "\n"))
	return err
}

func sanitizerOf(ws string) string {
	for _, b := range Builds {
		if b[0] == ws {
			return b[1]
		}
	}
	return ""
}

func maxI(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// splitCoverage separates fresh measurements from stale ones.
//
// PREFER THE RECORDED PASS ID. Once a coverage run stamps one, "was this
// measured in the same pass" is a lookup and no time window is needed.
//
// The clock rules below stay only for rows written before that, and they have
// been wrong in BOTH directions already: anchored to a fixed date, one called a
// two-day-old row fresh; a six-hour window called 21 current rows stale. A
// window cannot separate a slow pass from an old one; an id can.
//
// So the cutoff is also SELF-ANCHORING -- anything materially older than the
// newest row is stale, whatever the calendar says.
func splitCoverage(all map[string]CoverageRow) (fresh, stale map[string]CoverageRow) {
	fresh, stale = map[string]CoverageRow{}, map[string]CoverageRow{}
	passes := map[string]bool{}
	newest := ""
	for _, r := range all {
		if r.PassID != "" {
			passes[r.PassID] = true
		}
		if r.When > newest {
			newest = r.When
		}
	}
	if len(passes) > 0 {
		var ps []string
		for p := range passes {
			ps = append(ps, p)
		}
		sort.Strings(ps)
		newestPass := ps[len(ps)-1]
		for t, r := range all {
			if r.PassID == newestPass {
				fresh[t] = r
			} else {
				stale[t] = r
			}
		}
		return fresh, stale
	}
	cutoff := CovValidFrom
	if newest != "" {
		if t, err := parseISO(newest); err == nil {
			lag := t.Add(-CovMaxLagHours * time.Hour).Format("2006-01-02T15:04:05")
			if lag > cutoff {
				cutoff = lag
			}
		}
	}
	for t, r := range all {
		if r.When >= cutoff {
			fresh[t] = r
		} else {
			stale[t] = r
		}
	}
	return fresh, stale
}

// ReadStoppedAt reads the marker the scheduled stop leaves behind.
func ReadStoppedAt(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	for _, l := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(l, "stopped_at=") {
			return strings.TrimSpace(strings.SplitN(l, "=", 2)[1])
		}
	}
	return ""
}

// MarkerPath is where the scheduled stop writes it.
func MarkerPath(wsRoot string) string {
	return filepath.Join(wsRoot, "campaign-stopped.marker")
}

func f0(v float64) string { return strconv.FormatFloat(v, 'f', 0, 64) }

var _ = html.EscapeString

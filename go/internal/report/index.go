package report

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// The campaign history page: one row per archived run, and what the gates let
// through across all of them.
//
// EVERY NUMBER COMES FROM THE ARCHIVE'S OWN MANIFEST, never from the rendered
// report beside it. A report that is parsed to recover its own inputs has
// quietly become the source of truth for itself, and then a layout change is a
// data change.

// IndexData is the campaign history page.
type IndexData struct {
	Slug      string
	Generated time.Time
	Runs      []RunRow

	// FPChanged says the fingerprint changed while its DEFINITION stayed put:
	// rows either side describe different experiments.
	FPChanged bool
	// FPRedefined says the definition itself widened. The hash changed, the
	// experiment did not.
	FPRedefined bool

	Streaks    []Streak
	MoreStreak int // streaks beyond the 25 shown

	// HEAD -- what the newest run pinned. This is the input set a replay
	// would have to reproduce.
	Head       string
	Provenance []KV
	OSSDirty   bool
	OSSCommit  string
	FuzzerCols []string // workspace short names, in column order
	FuzzerRows []FuzzerRow
}

// KV is one provenance row.
// AnyMasked is whether ANY run masked a target, which is a different question
// from whether a target was masked across CONSECUTIVE runs.
//
// A METHOD, not a field: the section that needs it is reachable from more than
// one path, and a field computed in GatherIndex alone is stale everywhere
// else -- which is how the gate came to be written against Streaks in the
// first place.
func (d IndexData) AnyMasked() bool {
	for _, r := range d.Runs {
		if !r.Broken && r.Masked > 0 {
			return true
		}
	}
	return false
}

type KV struct{ K, V string }

// FuzzerRow is one target's binary fingerprint across the workspaces.
//
// The harness is half the experiment and used to go unrecorded.
type FuzzerRow struct {
	Target string
	SHAs   []string
}

// RunRow is one archived run, newest first.
type RunRow struct {
	Name   string // the archive directory
	Label  string // the date and time, from the directory name
	Broken bool   // MANIFEST.json present but unparseable

	Fingerprint string // config_fingerprint, or "?" when the run predates it
	Changed     bool   // the experiment moved here
	Redefined   bool   // only the definition of the hash moved here

	Corpus     int
	Delta      int
	HasDelta   bool
	Coverage   string // "12.34%" or ""
	CovTargets int    // how many targets that union covered
	CovStale   bool   // the newest measurement produced nothing; this is older
	Reproducer int

	HasReport bool

	// What this run's gates chose not to fail on.
	//
	// Acks and Degraded are counted as ENTRIES and RegimeSkipped as distinct
	// TARGETS, which looks inconsistent and is not: one target can be skipped
	// once per round, so the entry count of that column measures how many
	// rounds ran rather than how much was unguarded.
	Acks, Degraded, RegimeSkipped []string
	SkippedTargets                int
	Masked                        int
}

// Streak is a target masked in N consecutive runs, newest-first.
//
// A target masked once is a note; a target masked in every run for a month is
// a finding nobody has looked at. Only the history separates them.
type Streak struct {
	Target string
	Short  string // without the _fuzzer suffix every row would repeat
	Runs   int
	How    string
	Since  string
}

// manifest is the subset of MANIFEST.json this page reads.
type manifest struct {
	ConfigFingerprint string                          `json:"config_fingerprint"`
	FPVersion         int                             `json:"fp_version"`
	Corpus            map[string]struct{ Inputs int } `json:"corpus"`
	Reproducers       map[string]int                  `json:"reproducers"`

	ArchivedAt string `json:"archived_at"`
	Host       string `json:"host"`
	ToolCommit string `json:"tool_commit"`
	OSSFuzz    struct {
		Commit    string `json:"commit"`
		BaseImage string `json:"base_image"`
		Dirty     bool   `json:"dirty"`
	} `json:"oss_fuzz"`
	Harness struct {
		SourcesSHA256 string `json:"sources_sha256"`
		LastCommit    string `json:"last_commit"`
	} `json:"harness"`
	Builds map[string]struct {
		PGRefSHA string `json:"pg_ref_sha"`
	} `json:"builds"`
	Fuzzers map[string]map[string]string `json:"fuzzers"`
}

// gathered is the archived gather output the masking table reads.
type gathered struct {
	Masked struct {
		Acks          []struct{ Target string } `json:"acks"`
		Degraded      []struct{ Target string } `json:"degraded"`
		RegimeSkipped []struct{ Target string } `json:"regime_skipped"`
	} `json:"masked"`
}

// GatherIndex reads every archived run under a campaign, oldest first, then
// reverses -- the deltas are only meaningful in chronological order.
func GatherIndex(root, slug string) (IndexData, error) {
	d := IndexData{Slug: slug, Generated: time.Now().UTC()}
	dir := filepath.Join(root, slug)
	ents, err := os.ReadDir(dir)
	if err != nil {
		return d, err
	}
	names := make([]string, 0, len(ents))
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		// A manifest is what makes a directory a RUN, EXCEPT for the three
		// the campaign keeps for itself. `live/` has none, but `bundles/` and
		// `ws/` do -- so before this every bundle became a phantom row on the
		// history page, rendering ? and - across every column and flipping a
		// "definition widened" notice on a directory that is not a run.
		//
		// Excluded by name rather than by content: a genuine archive from
		// before fingerprints existed has no config_fingerprint either, and it
		// is still a run. The Python rendered it as ?, and so does this.
		switch e.Name() {
		case "live", "bundles", "ws":
			continue
		}
		if _, err := os.Stat(filepath.Join(dir, e.Name(), "MANIFEST.json")); err != nil {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)

	prevCorpus, prevFP, prevFPV := -1, "", -1
	fps := map[string]bool{}
	fpvs := map[int]bool{}

	for _, name := range names {
		rd := filepath.Join(dir, name)
		row := RunRow{
			Name:      name,
			Label:     runLabel(slug, name),
			HasReport: fileExists(filepath.Join(rd, "report", "index.html")),
		}
		b, err := os.ReadFile(filepath.Join(rd, "MANIFEST.json"))
		var m manifest
		if err != nil || json.Unmarshal(b, &m) != nil {
			// A manifest that will not parse is REPORTED, never skipped
			// silently -- an archive missing from the index looks exactly like
			// a run that never happened.
			row.Broken = true
			d.Runs = append(d.Runs, row)
			continue
		}

		row.Fingerprint = m.ConfigFingerprint
		if row.Fingerprint == "" {
			row.Fingerprint = "?"
		}
		fpv := m.FPVersion
		if fpv == 0 {
			fpv = 1
		}
		// Two ways the hash can differ, and they mean opposite things: the
		// EXPERIMENT moved, or the hash widened to cover an input it had been
		// missing. Both change the string; only the first invalidates a
		// comparison across the line.
		row.Redefined = prevFPV != -1 && fpv != prevFPV
		row.Changed = row.Fingerprint != "?" && prevFP != "" && prevFP != "?" &&
			row.Fingerprint != prevFP && !row.Redefined

		for _, c := range m.Corpus {
			row.Corpus += c.Inputs
		}
		if prevCorpus >= 0 {
			row.Delta, row.HasDelta = row.Corpus-prevCorpus, true
		}
		for _, n := range m.Reproducers {
			row.Reproducer += n
		}
		if cov, tgts, stale, ok := coverageOf(rd); ok {
			row.Coverage, row.CovTargets, row.CovStale = cov, tgts, stale
		}
		row.Acks, row.Degraded, row.RegimeSkipped = maskedOf(rd)
		row.SkippedTargets = len(union(row.RegimeSkipped))
		row.Masked = len(union(row.Acks, row.Degraded, row.RegimeSkipped))

		if row.Fingerprint != "?" {
			fps[row.Fingerprint] = true
		}
		fpvs[fpv] = true
		prevCorpus, prevFP, prevFPV = row.Corpus, row.Fingerprint, fpv
		d.Runs = append(d.Runs, row)
	}

	d.FPChanged = len(fps) > 1 && len(fpvs) == 1
	d.FPRedefined = len(fpvs) > 1
	d.Streaks = streaks(d.Runs)
	// Longest first, and only the top of the list: the length is the signal,
	// and a page that lists everything buries it. What is dropped is COUNTED,
	// never silently truncated.
	if len(d.Streaks) > 25 {
		d.MoreStreak = len(d.Streaks) - 25
		d.Streaks = d.Streaks[:25]
	}
	if len(names) > 0 {
		d.Head = names[len(names)-1]
		headProvenance(&d, filepath.Join(dir, d.Head))
	}

	// OLDEST FIRST for display, which is also the order the deltas were
	// computed in. A delta column only reads correctly downwards.
	return d, nil
}

// runLabel is the date and time of a run, from its directory name.
//
// Archives are <slug>-<date>-<time>[-<cfg8>], and the slug itself contains
// hyphens. Splitting from the RIGHT lands on the date while a run has no
// fingerprint suffix and on the time once it has one -- so the column silently
// switched from showing 20260828 to showing 214306 the moment fingerprinting
// was added, mixing two different quantities in one column. Strip the known
// slug prefix instead, which is unambiguous.
func runLabel(slug, name string) string {
	rest := strings.TrimPrefix(name, slug+"-")
	parts := strings.Split(rest, "-")
	if len(parts) >= 2 && allDigits(parts[0]) && allDigits(parts[1]) && len(parts[1]) >= 4 {
		return fmt.Sprintf("%s %s:%s", parts[0], parts[1][:2], parts[1][2:4])
	}
	if len(parts) > 0 {
		return parts[0]
	}
	return rest
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// coverageOf reads the newest line of the archived union series.
// coverageOf is a run's union coverage, from the newest measurement it made.
//
// THE NEWEST, not the newest that happened to work. The old reading took the
// last record with a non-zero line count, so a measurement that produced
// nothing left the PREVIOUS one standing in the column with nothing to say it
// was older -- coverage attributed to a run that had not managed to measure
// any. Falling back is still better than an empty column, but it has to say
// so.
//
// The target count travels with it because a union over 23 targets and a union
// over 46 are not the same measurement, and printed as a bare percentage they
// look identical. One run's file here holds both. It rides in the cell's title
// rather than its text: the rendered cells are checked against the Python this
// replaced, and widening a column is a change to the page, not a fix to it.
func coverageOf(runDir string) (cov string, targets int, stale bool, ok bool) {
	f, err := os.Open(filepath.Join(runDir, "series", "coverage-union.jsonl"))
	if err != nil {
		return "", 0, false, false
	}
	defer f.Close()

	type rec struct {
		Lines   struct{ Count, Covered int } `json:"lines"`
		Targets int                          `json:"targets"`
	}
	var all []rec
	dec := json.NewDecoder(f)
	for {
		var r rec
		if err := dec.Decode(&r); err != nil {
			break
		}
		all = append(all, r)
	}
	if len(all) == 0 {
		return "", 0, false, false
	}
	pct := func(r rec) string {
		return fmt.Sprintf("%.2f%%", 100*float64(r.Lines.Covered)/float64(r.Lines.Count))
	}
	if last := all[len(all)-1]; last.Lines.Count > 0 {
		return pct(last), last.Targets, false, true
	}
	// The newest measurement produced nothing. Show the newest that did, and
	// mark it, rather than presenting it as this run's result.
	for i := len(all) - 1; i >= 0; i-- {
		if all[i].Lines.Count > 0 {
			return pct(all[i]), all[i].Targets, true, true
		}
	}
	return "", 0, false, false
}

// maskedOf reads what a run's gates chose not to fail on, from its archived
// gather output -- never scraped back out of the rendered report.
func maskedOf(runDir string) (acks, degraded, skipped []string) {
	b, err := os.ReadFile(filepath.Join(runDir, "report", "data.json"))
	if err != nil {
		return nil, nil, nil
	}
	var g gathered
	if json.Unmarshal(b, &g) != nil {
		return nil, nil, nil
	}
	for _, x := range g.Masked.Acks {
		acks = append(acks, x.Target)
	}
	for _, x := range g.Masked.Degraded {
		degraded = append(degraded, x.Target)
	}
	for _, x := range g.Masked.RegimeSkipped {
		skipped = append(skipped, x.Target)
	}
	return acks, degraded, skipped
}

func union(lists ...[]string) []string {
	seen := map[string]bool{}
	var out []string
	for _, l := range lists {
		for _, s := range l {
			if !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
	}
	sort.Strings(out)
	return out
}

// streaks counts each target's masking backwards from the NEWEST run and stops
// at the first run where it was genuinely guarded.
//
// An unbroken streak is the claim being made, so a single clean run in the
// middle must end it. Sorted longest first, because length is the whole signal.
//
// Takes runs in chronological order.
func streaks(runs []RunRow) []Streak {
	type how map[string]map[string]bool
	per := make([]struct {
		Label string
		H     how
	}, 0, len(runs))
	for _, r := range runs {
		if r.Broken {
			continue
		}
		h := how{}
		add := func(ts []string, label string) {
			for _, t := range ts {
				if h[t] == nil {
					h[t] = map[string]bool{}
				}
				h[t][label] = true
			}
		}
		add(r.Acks, "acknowledged")
		add(r.Degraded, "below half its floor")
		add(r.RegimeSkipped, "no comparable floor")
		per = append(per, struct {
			Label string
			H     how
		}{r.Label, h})
	}

	targets := map[string]bool{}
	for _, p := range per {
		for t := range p.H {
			targets[t] = true
		}
	}
	var out []Streak
	for t := range targets {
		n := 0
		hows := map[string]bool{}
		since := ""
		for i := len(per) - 1; i >= 0; i-- {
			if per[i].H[t] == nil {
				break
			}
			n++
			for k := range per[i].H[t] {
				hows[k] = true
			}
			since = per[i].Label
		}
		if n == 0 {
			continue
		}
		var hl []string
		for k := range hows {
			hl = append(hl, k)
		}
		sort.Strings(hl)
		out = append(out, Streak{t, strings.TrimSuffix(t, "_fuzzer"), n,
			strings.Join(hl, ", "), since})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Runs != out[j].Runs {
			return out[i].Runs > out[j].Runs
		}
		return out[i].Target < out[j].Target
	})
	return out
}

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }

// RenderIndex writes the history page.
func RenderIndex(w io.Writer, d IndexData) error {
	t, err := template.New("index").Funcs(template.FuncMap{
		"comma": comma,
		// "+0" and "0" are different claims: the first says a run was
		// measured against its predecessor and found no growth, the second
		// says nothing at all.
		// template.HTML because html/template escapes a bare "+" to &#43;,
		// which is correct escaping and the wrong output for a delta column.
		"signed": func(n int) template.HTML {
			if n < 0 {
				return template.HTML("-" + comma(-n))
			}
			return template.HTML("+" + comma(n))
		},
		"deltaClass": func(r RunRow) string {
			switch {
			case !r.HasDelta:
				return "dim"
			case r.Delta > 0:
				return "delta-up"
			case r.Delta < 0:
				return "delta-dn"
			}
			return "dim"
		},
		"when": func(t time.Time) string {
			if t.IsZero() {
				return "—"
			}
			return t.Format("2006-01-02 15:04")
		},
	}).Parse(indexPage)
	if err != nil {
		return err
	}
	return t.Execute(w, d)
}

var indexPage = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Slug}} campaigns</title>
<style>
` + baseCSS + `
</style>
</head>
<body>
<div class="shell"><main>
<header class="masthead">
<div class="eyebrow">{{.Slug}} &middot; campaign history</div>
<h1>Every run, and how it moved</h1>
<p class="standfirst">One row per archived run, oldest first. Each links to
that run's own frozen report. Nothing here is recomputed from live state
&mdash; it all comes from write-once archives, so a run that happened cannot be
edited by a later one.</p>
</header>

{{if not .Runs}}
<section><h2>No runs archived yet</h2>
<p>Run <code>pgfuzz bundle</code> after a campaign ends.</p>
</section></main></div></body></html>
{{else}}

<section id="runs"><h2>Runs</h2>
<div class="eli5"><p>The <b>inputs</b> column is a hash of everything that
defines the experiment: the PostgreSQL commit, the patches, the plugin versions
and the fuzzer sources. Two runs sharing it are comparable. When it changes,
something underneath moved &mdash; the row says so, and comparing across that
line needs care.</p>
<p>It deliberately does <i>not</i> include this page or the report layout.
Redesigning a report changes its bytes; it must not change what a run was.</p></div>

<div class="wrap"><table class="runs"><tr>
<th>run</th><th>inputs</th><th>corpus</th><th>&Delta;</th>
<th>coverage</th><th>reproducers</th><th>report</th></tr>
{{range .Runs}}{{if .Broken}}<tr><td class="t">{{.Name}}</td><td colspan="6" class="dim">MANIFEST.json could not be parsed &mdash; archive present, contents unread</td></tr>
{{else}}<tr>
<td class="t">{{.Label}}</td>
<td class="cfg{{if .Changed}} warn{{end}}"><code>{{.Fingerprint}}</code>{{if .Changed}} &#9888;{{end}}{{if .Redefined}} &#8853;{{end}}</td>
<td>{{if .Corpus}}{{comma .Corpus}}{{else}}&mdash;{{end}}</td>
<td class="{{deltaClass .}}">{{if .HasDelta}}{{signed .Delta}}{{else}}&mdash;{{end}}</td>
<td{{if .CovStale}} class="warn"{{end}}{{if .CovTargets}} title="union over {{.CovTargets}} targets"{{end}}>{{if .Coverage}}{{.Coverage}}{{if .CovStale}} &#9888;{{end}}{{else}}&mdash;{{end}}</td>
<td>{{if .Reproducer}}{{comma .Reproducer}}{{else}}&mdash;{{end}}</td>
<td>{{if .HasReport}}<a href="{{.Name}}/report/index.html">open</a>{{else}}none{{end}}</td>
</tr>
{{end}}{{end}}</table></div>
{{if .FPChanged}}<div class="nb">The inputs hash changed during this history.
Rows either side of a change describe different experiments, and a corpus or
coverage difference across that line may be the change rather than the
fuzzing.</div>
{{else if .FPRedefined}}<div class="nb">&#8853; marks where the fingerprint
<i>definition</i> widened to cover an input it had not been recording &mdash;
the hash changed, the experiment did not. Runs either side are still
comparable; what changed is how much of them is pinned. Only &#9888; means an
input actually moved.</div>
{{end}}</section>

{{if or .AnyMasked .Streaks}}
<section id="masked"><h2>What the gates let through, run by run</h2>
<div class="eli5"><p>Every rule that stops a ratchet crying wolf also hides
something. Three do it here: an <b>acknowledgement</b> suppresses a target
outright, the <b>tolerance</b> passes anything above a tenth of the record, and
a floor earned under a different configuration is <b>skipped as not
comparable</b>.</p>
<p>Each is defensible for one run. Across many runs they become the question
this table answers: what has been quietly unguarded, and for how long.</p></div>

<div class="wrap"><table class="runs"><tr><th>run</th>
<th>acknowledged</th><th>under half their floor</th>
<th>no floor enforced</th><th>total masked</th></tr>
{{range .Runs}}{{if not .Broken}}{{if .Masked}}<tr><td class="t">{{.Label}}</td>
<td>{{len .Acks}}</td><td>{{len .Degraded}}</td><td>{{.SkippedTargets}}</td>
<td class="warn">{{.Masked}}</td></tr>
{{end}}{{end}}{{end}}</table></div>

{{if .Streaks}}
<h3>Masked without a break, counting back from the newest run</h3>
<p>A target here has not been genuinely guarded for the number of consecutive
runs shown. The longest streaks are the ones to read first &mdash; they are
where a regression could have arrived unnoticed.</p>
<div class="wrap"><table class="cells"><tr><th>Target</th>
<th>Runs</th><th>How</th><th>Since</th></tr>
{{range .Streaks}}<tr><td class="t">{{.Short}}</td><td>{{.Runs}}</td>
<td style="text-align:left">{{.How}}</td><td>{{.Since}}</td></tr>
{{end}}</table></div>
{{if .MoreStreak}}<p class="dim">{{.MoreStreak}} more not listed.</p>
{{end}}
{{else}}<p class="dim">No target was masked in two consecutive runs, so there
is no streak to report. The table above still stands: masking happened.</p>
{{end}}</section>
{{end}}

<section id="head"><h2>HEAD &mdash; {{.Head}}</h2>
<p>What the newest run pinned. This is the input set a replay would have to
reproduce.</p>
<div class="wrap"><table class="runs"><tr><th>what</th><th>value</th></tr>
{{range .Provenance}}<tr><td class="t">{{.K}}</td><td>{{.V}}</td></tr>
{{end}}</table></div>
{{if .OSSDirty}}<div class="nb">The OSS-Fuzz clone has <b>modified tracked
files</b>. It is meant to be a pure substrate &mdash; harnesses reach it as
symlinks back into this repo &mdash; so the commit above no longer describes
what actually built these targets.</div>
{{else if .OSSCommit}}<p class="dim">The OSS-Fuzz clone is unmodified: every
<code>projects/pgfuzz-*</code> entry is a symlink back into this repository.
libFuzzer is linked statically into every target from the base image, which is
pinned separately from the commit because builds run with
<code>--no-pull</code> &mdash; so both are recorded.</p>
{{end}}
{{if .FuzzerRows}}<h3>Fuzzer binaries</h3>
<p>The harness is half the experiment and used to go unrecorded. These are the
binaries that produced the numbers above.</p>
<div class="wrap"><table class="runs"><tr><th>target</th>{{range .FuzzerCols}}<th>{{.}}</th>{{end}}</tr>
{{range .FuzzerRows}}<tr><td class="t">{{.Target}}</td>{{range .SHAs}}<td>{{.}}</td>{{end}}</tr>
{{end}}</table></div>
{{end}}</section>

<footer><p class="dim">Generated from {{len .Runs}} archived run(s). Archives
are write-once; this page is derived and can be rebuilt at any time with
<code>pgfuzz index</code>. Self-contained: no external stylesheets, fonts or
scripts, and every link is relative &mdash; so it works from the directory it
lives in, which is the point of an archive.</p></footer>
</main></div>
</body>
</html>
{{end}}
`

// headProvenance fills in what the newest run pinned.
func headProvenance(d *IndexData, runDir string) {
	b, err := os.ReadFile(filepath.Join(runDir, "MANIFEST.json"))
	var m manifest
	if err != nil || json.Unmarshal(b, &m) != nil {
		return
	}
	fpv := m.FPVersion
	if fpv == 0 {
		fpv = 1
	}
	d.Provenance = []KV{
		{"archived", m.ArchivedAt},
		{"host", m.Host},
		{"tool commit", m.ToolCommit},
		{"inputs hash", m.ConfigFingerprint},
		{"fingerprint definition", fmt.Sprintf("v%d", fpv)},
		{"oss-fuzz commit", m.OSSFuzz.Commit},
		{"base image (libFuzzer)", m.OSSFuzz.BaseImage},
		{"harness sources", m.Harness.SourcesSHA256},
		{"harness commit", m.Harness.LastCommit},
	}
	var wss []string
	for ws := range m.Builds {
		wss = append(wss, ws)
	}
	sort.Strings(wss)
	for _, ws := range wss {
		sha := m.Builds[ws].PGRefSHA
		if len(sha) > 16 {
			sha = sha[:16]
		}
		d.Provenance = append(d.Provenance, KV{ws + " pg_ref_sha", sha})
	}
	for i := range d.Provenance {
		if d.Provenance[i].V == "" {
			d.Provenance[i].V = "—"
		}
	}

	// The build substrate is a real input even when it never changes. Saying
	// so only when it is forked would make silence ambiguous.
	d.OSSDirty, d.OSSCommit = m.OSSFuzz.Dirty, m.OSSFuzz.Commit

	if len(m.Fuzzers) == 0 {
		return
	}
	var cols []string
	for ws := range m.Fuzzers {
		cols = append(cols, ws)
	}
	sort.Strings(cols)
	targets := map[string]bool{}
	for _, per := range m.Fuzzers {
		for t := range per {
			targets[t] = true
		}
	}
	var ts []string
	for t := range targets {
		ts = append(ts, t)
	}
	sort.Strings(ts)
	for _, ws := range cols {
		// The column head is the workspace's last segment: the slug is
		// repeated in every one of them and carries no information here.
		if i := strings.LastIndex(ws, "-"); i >= 0 {
			d.FuzzerCols = append(d.FuzzerCols, ws[i+1:])
		} else {
			d.FuzzerCols = append(d.FuzzerCols, ws)
		}
	}
	for _, t := range ts {
		row := FuzzerRow{Target: strings.TrimSuffix(t, "_fuzzer")}
		for _, ws := range cols {
			v := m.Fuzzers[ws][t]
			if v == "" {
				v = "—"
			}
			row.SHAs = append(row.SHAs, v)
		}
		d.FuzzerRows = append(d.FuzzerRows, row)
	}
}

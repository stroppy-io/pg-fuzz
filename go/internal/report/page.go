package report

// page is the whole document.
//
// The palette is defined on bare :root as the complete LIGHT set, then
// redefined for dark under prefers-color-scheme guarded so an explicit light
// choice wins, and again under [data-theme="dark"] so a toggle wins in both
// directions. A colour whose only definition sits inside a media query never
// applies in the un-stamped state -- which is what most readers are in -- and
// the page renders one theme's text on the other theme's ground.
//
// body sets an explicit background from a token: the host paints its own
// ground behind the page, so a transparent body silently borrows it.
const page = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Slug}} — fuzzing report</title>
<style>
:root {
  --paper:#f2f1ee; --surface:#fbfaf8; --ink:#1b1a18; --ink-2:#4a4744;
  --slate:#6d6963; --rule:#d9d5cf; --rule-2:#e8e5e0;
  --accent:#9a4a1f; --accent-dim:#c07a4e;
  --ok:#2f6d4f; --warn:#8a6410; --bad:#a3232f;
  --serif:"Iowan Old Style",Palatino,"Book Antiqua",Georgia,serif;
  --sans:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Arial,sans-serif;
  --mono:ui-monospace,"SF Mono",SFMono-Regular,Menlo,Consolas,monospace;
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    --paper:#14140f; --surface:#1c1c17; --ink:#e8e5df; --ink-2:#c0bcb4;
    --slate:#8d8880; --rule:#33322b; --rule-2:#26251f;
    --accent:#d9884f; --accent-dim:#a86b42;
    --ok:#63b58f; --warn:#d2a548; --bad:#e2707a;
  }
}
:root[data-theme="dark"] {
  --paper:#14140f; --surface:#1c1c17; --ink:#e8e5df; --ink-2:#c0bcb4;
  --slate:#8d8880; --rule:#33322b; --rule-2:#26251f;
  --accent:#d9884f; --accent-dim:#a86b42;
  --ok:#63b58f; --warn:#d2a548; --bad:#e2707a;
}
*{box-sizing:border-box}
body{margin:0;background:var(--paper);color:var(--ink);
  font-family:var(--sans);font-size:16px;line-height:1.6;
  -webkit-font-smoothing:antialiased}
main{max-width:62rem;margin:0 auto;padding:3rem 1.5rem 6rem}
h1{font-family:var(--serif);font-size:2.1rem;line-height:1.15;margin:0 0 .4rem;
  text-wrap:balance;letter-spacing:-.01em}
h2{font-family:var(--serif);font-size:1.35rem;margin:3rem 0 .9rem;
  padding-bottom:.4rem;border-bottom:1px solid var(--rule);text-wrap:balance}
.sub{color:var(--slate);margin:0 0 2.5rem;font-size:.95rem}
.eyebrow{font-family:var(--mono);font-size:.72rem;letter-spacing:.16em;
  text-transform:uppercase;color:var(--accent);margin:0 0 .5rem}
.big{display:flex;flex-wrap:wrap;gap:2.5rem;margin:1.5rem 0 .5rem}
.big div{min-width:8rem}
.big .v{font-family:var(--serif);font-size:2rem;line-height:1;
  font-variant-numeric:tabular-nums}
.big .k{color:var(--slate);font-size:.8rem;margin-top:.3rem}
.wrap{overflow-x:auto;margin:1rem 0}
table{border-collapse:collapse;width:100%;font-size:.9rem}
th,td{text-align:left;padding:.45rem .8rem .45rem 0;
  border-bottom:1px solid var(--rule-2)}
th{font-family:var(--mono);font-size:.7rem;letter-spacing:.1em;
  text-transform:uppercase;color:var(--slate);font-weight:600}
td.n,th.n{text-align:right;font-variant-numeric:tabular-nums;
  font-family:var(--mono);font-size:.85rem}
code{font-family:var(--mono);font-size:.85em;background:var(--surface);
  border:1px solid var(--rule-2);border-radius:3px;padding:.05em .3em}
.note{background:var(--surface);border:1px solid var(--rule);
  border-left:2px solid var(--accent-dim);padding:.9rem 1.1rem;margin:1.2rem 0}
.note p{margin:0}
.muted{color:var(--slate)}
.bad{color:var(--bad)}
.ok{color:var(--ok)}
footer{margin-top:4rem;padding-top:1rem;border-top:1px solid var(--rule);
  color:var(--slate);font-size:.82rem}
</style>
</head>
<body>
<main>
<p class="eyebrow">fuzzing campaign</p>
<h1>{{.Slug}}</h1>
<p class="sub">{{if .RunID}}run <code>{{.RunID}}</code> · {{end}}started {{when .Started}} · {{dur .Elapsed}} elapsed · rendered {{when .Generated}}</p>

<section>
<h2>What the run did</h2>
<div class="big">
  <div><div class="v">{{comma .Execs}}</div><div class="k">executions</div></div>
  <div><div class="v">{{comma .NewInputs}}</div><div class="k">new inputs</div></div>
  <div><div class="v">{{.Slices}}</div><div class="k">slices, {{.Rounds}} rounds</div></div>
  <div><div class="v">{{.Artifacts}}</div><div class="k">raw artifacts</div></div>
</div>
<div class="note"><p><strong>An artifact is not a finding.</strong> One saved
input that made a target crash — and a single defect hit repeatedly produces
hundreds of them. A finding is a distinct defect after triage. Confusing the
two overstates a result by more than tenfold, which is why both appear here
with different names.</p></div>
{{if .Workspaces}}
<div class="wrap">
<table>
<thead><tr><th>Workspace</th><th class="n">Slices</th><th class="n">Executions</th><th class="n">New</th><th class="n">Artifacts</th><th class="n">Edges</th></tr></thead>
<tbody>
{{range .Workspaces}}<tr><td><code>{{.Name}}</code></td><td class="n">{{.Slices}}</td><td class="n">{{comma .Execs}}</td><td class="n">{{comma .NewInputs}}</td><td class="n">{{.Artifacts}}</td><td class="n">{{comma .Cov}}</td></tr>
{{end}}</tbody>
</table>
</div>
{{end}}
</section>

{{if .UnderTest}}
<section>
<h2>What was tested</h2>
<p class="muted">As the campaign sealed it. A run against a patched tree or a
set of extensions is not reproducible unless it says which — so the commit that
was <em>compiled</em> is recorded here, not the branch name, which moves.</p>
<div class="wrap">
<table>
<thead><tr><th>Workspace</th><th>Ref</th><th>Commit</th><th>Sanitizer</th><th>Patches</th><th>Extensions</th></tr></thead>
<tbody>
{{range .UnderTest}}<tr>
<td><code>{{.Name}}</code>{{if not .BuildOK}} <span class="bad">build failed</span>{{end}}</td>
<td><code>{{.Ref}}</code></td>
<td><code>{{short .SHA}}</code></td>
<td>{{.Sanitizer}}</td>
<td>{{if .Patches}}{{range .Patches}}<code>{{.}}</code><br>{{end}}{{else}}<span class="muted">none</span>{{end}}</td>
<td>{{if .Plugins}}{{range .Plugins}}<code>{{.}}</code> {{end}}{{else}}<span class="muted">none</span>{{end}}</td>
</tr>
{{end}}</tbody>
</table>
</div>
{{if not .Sealed}}<div class="note"><p><strong>This campaign was not
sealed.</strong> It shared each workspace's corpus, so its coverage cannot be
re-measured from this slug alone: the corpus it ran against has since moved
on.</p></div>{{end}}
</section>
{{end}}

{{with .Coverage}}
<section>
<h2>Coverage</h2>
<p class="muted">All {{.Targets}} targets combined, each line counted once.</p>
<div class="wrap">
<table>
<thead><tr><th>Measure</th><th class="n">Covered</th><th class="n">Total</th><th class="n">Share</th></tr></thead>
<tbody>
<tr><td>lines</td><td class="n">{{comma .Lines.Covered}}</td><td class="n">{{comma .Lines.Count}}</td><td class="n">{{pct .Lines}}</td></tr>
<tr><td>functions</td><td class="n">{{comma .Functions.Covered}}</td><td class="n">{{comma .Functions.Count}}</td><td class="n">{{pct .Functions}}</td></tr>
<tr><td>regions</td><td class="n">{{comma .Regions.Covered}}</td><td class="n">{{comma .Regions.Count}}</td><td class="n">{{pct .Regions}}</td></tr>
<tr><td>branches</td><td class="n">{{comma .Branches.Covered}}</td><td class="n">{{comma .Branches.Count}}</td><td class="n">{{pct .Branches}}</td></tr>
<tr><td>files entered</td><td class="n">{{comma .FilesSeen}}</td><td class="n">{{comma .Files}}</td><td class="n"></td></tr>
</tbody>
</table>
</div>
<div class="note"><p>A union is <strong>not</strong> its largest member. Every
per-target profile is merged and <code>llvm-cov</code> counts each line once.
Plugin objects are passed explicitly, because the OSS-Fuzz helper builds its
object list from <code>DT_NEEDED</code> and PostgreSQL <code>dlopen</code>s its
extensions — so without that, a report that looks complete covers only
core.</p></div>
</section>
{{end}}

{{if .Findings}}
<section>
<h2>Findings on record</h2>
<div class="big">
  <div><div class="v">{{len .Findings}}</div><div class="k">distinct findings, triaged</div></div>
</div>
<div class="note"><p><strong>These are the project's standing findings, not
this run's alone.</strong> A finding is a write-up a person made after triage,
and write-ups are not stamped with the campaign that produced them — so they
cannot be attributed to one run, and this page does not pretend otherwise. What
<em>this</em> run produced is the artifact count above.</p></div>
<div class="wrap">
<table>
<thead><tr><th>Area</th><th class="n">Findings</th></tr></thead>
<tbody>
{{range .ByArea}}<tr><td>{{.Area}}</td><td class="n">{{.Count}}</td></tr>
{{end}}</tbody>
</table>
</div>
<h2>Which fuzzer found them</h2>
<div class="wrap">
<table>
<thead><tr><th>Target</th><th class="n">Findings</th></tr></thead>
<tbody>
{{range .ByTarget}}<tr><td><code>{{.Target}}</code></td><td class="n">{{.Count}}</td></tr>
{{end}}
<tr><td class="muted">systemic — several targets at once</td><td class="n">{{.Systemic}}</td></tr>
{{if .Unattributed}}<tr><td class="muted">not attributable from the write-up</td><td class="n">{{.Unattributed}}</td></tr>{{end}}
</tbody>
</table>
</div>
<p class="muted">A write-up naming several targets is left as systemic on
purpose. Those are things that hit many at once — a timeout that never fires, a
budget eaten by replay — and pinning one on whichever target is mentioned first
would invent a precision the evidence does not have.</p>
</section>
{{end}}

<footer>
Generated by <code>pgfuzz report</code>. Self-contained: no external
stylesheets, fonts or scripts, so it renders from a directory with no network.
</footer>
</main>
</body>
</html>
`

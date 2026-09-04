// Package tui shows what a campaign is doing.
//
// IT READS THE MODEL, NOT THE LOGS
// ================================
// The Python dashboard derives everything by scraping run logs and guessing:
// which workspaces are in this campaign, whether a target has run, where a
// round began. Each guess is a place to be wrong, and each has been -- it
// reported 76 hours elapsed from a two-day-dead log, and it resolved "swept"
// from the driver's own account, so a hole in the RUN and a hole in the
// DISPLAY looked identical.
//
// The series is the record. A row exists because a slice finished, and the
// campaign's live/ says what is running now. Nothing here infers a fact that
// is written down somewhere.
package tui

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"pgfuzz/internal/breakdown"
	"pgfuzz/internal/coverage"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"pgfuzz/internal/campaign"
)

// Cell is one (workspace, target) square.
type Cell struct {
	Swept bool
	// Corpus after the newest slice for this target. Per target, because each
	// has its own corpus directory and a workspace total is their sum.
	Corpus   int
	Running  bool
	Execs    int
	NewUnits int
	// Artifacts is what THIS round produced; ArtifactsAll is the target's
	// total across the campaign. Both are needed: the cell shows the total, so
	// a clean round cannot hide earlier reproducers, and colours it by whether
	// this round added any.
	Artifacts    int
	ArtifactsAll int
	Round        int
	// LoggedOnly means a log exists for this target but no series row does.
	//
	// A HOLE IN THE RUN AND A HOLE IN THE DISPLAY ARE DIFFERENT. Swept was
	// decided from the series alone, so a slice that ran and died before
	// writing its row was indistinguishable from a target that never started
	// -- and the detail view called both "never ran". The shell resolved this
	// from three sources for exactly that reason.
	LoggedOnly bool
}

// Row is one workspace.
type Row struct {
	Name string
	// Building is drawn on the MATRIX, not as a note beside it. Phase 1 is the
	// long stretch of a campaign and the grid had no symbol for it: a workspace
	// mid-build showed blank across its whole row, indistinguishable from one
	// that had not been started. On a five-entry matrix that is most of the
	// screen saying "nothing here" while every core is busy.
	Building bool
	// Built and Failed come from the campaign's manifest: a workspace whose
	// build failed is not the same as one that has not been built, and drawing
	// both as "nothing here" is how a five-entry matrix says nothing at all.
	Built bool
	// Freshness separates a build this run made from one an earlier run left
	// behind, which "Built" alone cannot.
	Freshness campaign.BuildFreshness
	// Covering is the target this workspace is measuring coverage for, or "".
	Covering string
	Failed   bool
	// Corpus, CorpusNew and CovPct are the three columns the old dashboard
	// carried beside the grid: size now, what this round added, and what the
	// coverage build measured.
	Round     int
	Corpus    int
	CorpusNew int
	CovPct    float64
	// SHA is the RESOLVED commit, not the ref name: "origin/master" says
	// nothing about which master, and a branch-HEAD finding is only reportable
	// against a specific commit.
	SHA string

	Cells   map[string]Cell
	Execs   int
	New     int
	Arts    int
	Swept   int
	Running string
}

// Model is everything the screen needs.
type Model struct {
	Slug    string
	RunID   string
	Started time.Time
	// LastSlice is when the newest slice was recorded, which is where a dead
	// campaign's clock stops.
	LastSlice time.Time
	// Hours is the campaign's requested length, from its own state file.
	//
	// DECLARED AND NEVER ASSIGNED until now -- the exact reader-without-writer
	// shape this package's own doc comment describes. campaign.State.Hours sat
	// in campaign.json unread, so the header showed elapsed with nothing to
	// measure it against and a reader could not tell 2h into 24 from 2h into 2.
	Hours float64
	// CovDone and CovTotal are how far through a coverage pass the machine is.
	// A coverage pass is BOUNDED, which is what makes a completion figure
	// meaningful here where it is meaningless for a fuzzing round.
	CovDone, CovTotal int
	// RowsTotal is how many rows there were before filtering, and Filter is
	// which filter is on. Both are drawn, because a short grid that does not
	// say it is filtered reads as a campaign that lost workspaces.
	RowsTotal int
	Filter    string
	// Snapshot means this frame is going into a LOG, not onto a terminal.
	//
	// A dashboard written to a CI step log is read once, by somebody who
	// cannot press anything, so "q quit  g grid  d detail" is furniture at
	// best and an invitation to try something impossible at worst. The
	// footer's OTHER half -- whatever went wrong reading docker -- still
	// matters and still prints.
	Snapshot bool
	// Breakdown is crashes by component, for the view `b` opens. Filled only
	// in LoadWithPanels, which is the path that knows where the workspaces
	// are.
	Breakdown []BreakdownRow
	// History is the other campaigns under this root, newest first, for the
	// view `h` opens. A dashboard could not previously answer "what did the
	// last five campaigns find" without leaving it.
	History []HistoryRow
	// SliceStats is the runs slice accounting: finished, in flight, and how
	// many reported nothing. Silence was detected only at gate time, which is
	// after the round.
	SliceStats Slices
	Live       bool
	Round      int
	Targets    []string
	Rows       []Row
	Slices     int
	TotalExec  int
	TotalNew   int
	TotalArts  int
	Err        string

	// Workspaces being BUILT right now. A campaign builds into its own
	// directory before it sweeps, and before this the dashboard said "no
	// series yet" and showed nothing while 32 cores were compiling -- work
	// the tool was doing and could not see. The dashboard is meant to be the
	// single place you look, so it has to notice a phase that writes no
	// slices.
	Building []string

	// The panels the grid cannot show: is it still climbing, and is the
	// machine healthy enough to keep going.
	// Sealed: this campaign owns its corpus and can be moved and re-measured.
	Sealed bool
	// Phase and Activity are the two lines above the grid. A campaign that is
	// building says so, and NOW: names what is happening this second -- which
	// is the difference between a dashboard and a report.
	Phase    string
	Activity string
	Built    int

	Growth []string
	System SystemStats
	Status string
}

// LoadWithPanels builds the model and the panels beside it.
//
// The grid answers "what has run"; these answer "is it still finding
// anything" and "will the machine let it finish". A dashboard with only the
// first is how a campaign runs for hours against a full disk.
func LoadWithPanels(campaignsRoot, slug, repo, wsRoot string) Model {
	m := Load(campaignsRoot, slug)
	var names []string
	for _, r := range m.Rows {
		names = append(names, r.Name)
	}
	// FALL BACK TO THE RECORD when the campaign series is empty.
	//
	// The grid is built from the campaign's own series, which a campaign run
	// under an older driver never wrote. The ratchet series did record those
	// rounds, so the growth curves exist even when the grid is blank -- and a
	// dashboard that shows neither, because one file is missing, reports a
	// campaign with history as a campaign with none.
	if len(names) == 0 {
		names = workspacesInSeries(
			filepath.Join(repo, "scripts", "ratchet-series.jsonl"), slug)
	}
	covSeries := filepath.Join(repo, "scripts", "coverage-series.jsonl")
	// The cov column, which had a renderer and no writer. Filled here rather
	// than in Load because only this path knows where the coverage series is.
	for i := range m.Rows {
		m.Rows[i].CovPct = CoveragePct(covSeries, m.Rows[i].Name)
	}
	m.Growth = GrowthPanel(
		filepath.Join(repo, "scripts", "ratchet-series.jsonl"),
		covSeries, names, 24)
	// A COVERAGE PASS IS NOT IDLE. helper.py names its own containers, so
	// RunningNow cannot see them and the header said "idle -- no container
	// running" for the whole of phase 3. The pass records itself instead.
	for i := range m.Rows {
		if l := coverage.ReadLive(filepath.Join(wsRoot, m.Rows[i].Name)); l != nil {
			m.Rows[i].Covering = l.Target
			m.CovDone, m.CovTotal = l.Done, l.Total
		}
	}
	if m.CovTotal > 0 {
		// Stated with its progress, because a coverage pass is BOUNDED --
		// which is what makes a completion figure meaningful here and
		// meaningless for a fuzzing round.
		var covering []string
		for _, row := range m.Rows {
			if row.Covering != "" {
				covering = append(covering, row.Name+" "+Code(row.Covering))
			}
		}
		sort.Strings(covering)
		m.Activity = fmt.Sprintf("measuring coverage [%d/%d]   %s",
			m.CovDone, m.CovTotal, strings.Join(covering, "   "))
	}
	// THE COMPONENT VIEW'S DATA. Scanned from the crash logs a slice writes,
	// for the selected campaign's workspaces -- the same source `pgfuzz
	// breakdown` uses, so the dashboard and the command cannot disagree.
	m.Breakdown = loadBreakdown(wsRoot, m.Rows, m.Targets)
	m.History = History(campaignsRoot, 25)
	m.System = ReadSystem(wsRoot)
	m.Status = StatusLine(m.System)
	return m
}

// Load builds the model from a campaign directory.
func Load(campaignsRoot, slug string) Model {
	m := Model{Slug: slug}
	dir := filepath.Join(campaignsRoot, slug)

	if b, err := os.ReadFile(filepath.Join(dir, "live", "campaign.json")); err == nil {
		var st campaign.State
		if json.Unmarshal(b, &st) == nil {
			m.RunID = st.RunID
			// Recorded as a string in the state file; a campaign whose length
			// cannot be parsed shows no deadline rather than a wrong one.
			if h, err := strconv.ParseFloat(st.Hours, 64); err == nil {
				m.Hours = h
			}
			if t, err := time.Parse(time.RFC3339, st.Started); err == nil {
				m.Started = t
			}
			// Alive means the process is there, not that a file exists: a
			// marker outlives a kill -9, and a dashboard that trusts it
			// reports a dead campaign as running indefinitely.
			m.Live = st.PID > 0 && processAlive(st.PID)
		}
	}

	// Read BEFORE the series, so a campaign still in its build phase is shown
	// as building rather than as an error.
	m.Building = campaign.Building(dir, 5*time.Minute)

	// The commits come from the campaign's OWN manifest. A sealed slug has to
	// be readable where it stands, and the workspace it was built from may not
	// exist on the machine looking at it.
	shas := map[string]string{}
	built, failed := map[string]bool{}, map[string]bool{}
	var manTargets []string
	if man, err := campaign.ReadManifest(dir); err == nil {
		m.Sealed = man.Sealed
		for _, e := range man.Entries {
			// THE ORIOLEDB COMMIT WINS WHERE THERE IS ONE, as it did before:
			// for an OrioleDB workspace the PostgreSQL sha says which base
			// the engine was built against, not which engine, and the engine
			// is what the run is testing. short10 rejects the placeholders,
			// which is what stopped `(not built)` displacing a real commit.
			shas[e.Workspace] = commitFor(e.SHA, e.OrioleDBSHA)
			manTargets = append(manTargets, e.Targets...)
			built[e.Workspace] = e.BuildOK
			failed[e.Workspace] = !e.BuildOK
		}
	}

	byWS := map[string]*Row{}
	seenTarget := map[string]bool{}

	// THE GRID IS THE CAMPAIGN'S DECLARED WORKSPACES, not the ones that have
	// already produced a slice. Building it from the series alone meant the
	// whole dashboard was empty for the twenty minutes of a build phase --
	// "no series yet" and nothing else, while every core on the box was busy.
	for _, name := range declared(dir) {
		byWS[name] = &Row{Name: name, Cells: map[string]Cell{}}
	}
	// Targets likewise: the manifest knows them once a build has finished, and
	// before that there are simply no columns to draw.
	if len(manTargets) == 0 {
		manTargets = DefaultTargets()
	}
	for _, e := range manTargets {
		seenTarget[e] = true
	}

	// Cached: this runs once a second and the file changes every few minutes.
	rows, err := (campaign.Series{Path: filepath.Join(dir, "series.jsonl")}).ReadCached()
	if err != nil {
		if len(m.Building) == 0 && len(byWS) == 0 {
			m.Err = "no series yet"
		}
		rows = nil
	}
	m.Slices = len(rows)
	for _, r := range rows {
		w := byWS[r.Workspace]
		if w == nil {
			w = &Row{Name: r.Workspace, Cells: map[string]Cell{}}
			byWS[r.Workspace] = w
		}
		c := w.Cells[r.Target]
		// PER ROUND, not cumulative. A campaign runs nine or more rounds over
		// the same targets, so a cumulative grid goes solid after round one
		// and then shows nothing about what is happening now.
		if r.Round > c.Round {
			// TOTAL SURVIVES THE ROUND BOUNDARY, this round's does not.
			//
			// Only the per-round figure was kept, so from round 2 the grid
			// could be entirely clean while the header read "reproducers 12"
			// and the row's repro column read 12 -- with no cell saying where.
			// The Python showed the target's TOTAL in the cell and coloured it
			// red only when something arrived this round; that is the
			// distinction the colour carries, and the number should not.
			c = Cell{Round: r.Round, Corpus: c.Corpus, ArtifactsAll: c.ArtifactsAll}
		}
		c.Swept = true
		c.Execs += r.Execs
		c.NewUnits += r.NewUnits
		c.Artifacts += r.Artifacts
		c.ArtifactsAll += r.Artifacts
		// Newest wins, not a sum: Corpus is a level, not an increment, and
		// adding them would report a corpus several times its real size.
		if r.Corpus > 0 {
			c.Corpus = r.Corpus
		}
		if r.Round > c.Round {
			c.Round = r.Round
		}
		w.Cells[r.Target] = c
		w.Execs += r.Execs
		w.Arts += r.Artifacts
		// New units are THIS ROUND's, because the column is headed +new and a
		// campaign total in a per-round column reads as growth exceeding the
		// corpus it grew -- which it did: corpus 280.9k, +new 561.5k.
		if r.Round > w.Round {
			w.Round = r.Round
			w.New = 0
		}
		w.New += r.NewUnits
		seenTarget[r.Target] = true
		if r.Round > m.Round {
			m.Round = r.Round
		}
		m.TotalExec += r.Execs
		m.TotalNew += r.NewUnits
		m.TotalArts += r.Artifacts
		if t, err := time.Parse(time.RFC3339, r.Started); err == nil && t.After(m.LastSlice) {
			m.LastSlice = t
		}
	}
	for _, w := range byWS {
		for _, c := range w.Cells {
			// Swept THIS round: the grid answers "how far has this round
			// got", and after round one a cumulative count is always 23/23.
			if c.Swept && c.Round == w.Round {
				w.Swept++
			}
			w.Corpus += c.Corpus
		}
		w.CorpusNew = w.New
	}

	// Column order follows the table, not the alphabet: it is the order people
	// have been reading this grid in, and an unknown target goes on the end.
	for _, c := range codes {
		if seenTarget[c[0]] {
			m.Targets = append(m.Targets, c[0])
			delete(seenTarget, c[0])
		}
	}
	var extra []string
	for t := range seenTarget {
		extra = append(extra, t)
	}
	sort.Strings(extra)
	m.Targets = append(m.Targets, extra...)

	// A workspace the manifest has an entry for is DONE building, whether it
	// succeeded or not. Freshness alone left a FAILED build spinning ◐ for the
	// whole window -- and the header calling it "PHASE 1 BUILDING" while round
	// 1 was already sweeping another workspace.
	if len(built) > 0 {
		var still []string
		for _, n := range m.Building {
			if _, done := built[n]; !done {
				still = append(still, n)
			}
		}
		m.Building = still
	}

	// A workspace that is BUILDING has no series rows yet, so it would not
	// appear in the grid at all -- the row has to be created for it, or the
	// build is invisible exactly when it is the only thing happening.
	for _, name := range m.Building {
		if byWS[name] == nil {
			byWS[name] = &Row{Name: name, Cells: map[string]Cell{}}
		}
		byWS[name].Building = true
	}

	// THE LOGS ARE THE SECOND SOURCE. A target with a log and no series row
	// ran; the record is what is missing, and saying "never ran" of it sends
	// somebody to look for a container that did exist.
	for name, w := range byWS {
		data := campaign.WSDir(dir, name)
		if _, err := os.Stat(data); err != nil {
			continue // unsealed: its logs are in the workspace, not the slug
		}
		for _, t := range m.Targets {
			c := w.Cells[t]
			if c.Swept {
				continue
			}
			hits, _ := filepath.Glob(filepath.Join(data, "artifacts", t, "run-*.log*"))
			if len(hits) > 0 {
				c.LoggedOnly = true
				w.Cells[t] = c
			}
		}
	}

	// The slice accounting, from the same rows the grid is built from. In
	// flight is what docker says is running now, which the series cannot know.
	m.SliceStats = SliceStats(rows, len(RunningNow()), m.Started, time.Now())

	running := RunningNow()
	for name, w := range byWS {
		w.SHA = shas[name]
		// Built from the directory, so it is right during the build phase too;
		// the manifest only adds why a build FAILED, which it can only know
		// once every build has been attempted.
		// Three states: built by this run, left over from an earlier one, or
		// never. The middle one used to read as "built".
		w.Freshness = campaign.Freshness(dir, name, m.Started)
		w.Built = w.Freshness == campaign.FreshBuild
		if b, ok := built[name]; ok {
			w.Built, w.Failed = b, failed[name]
		}
		if t, ok := running[name]; ok {
			w.Running = t
			c := w.Cells[t]
			c.Running = true
			w.Cells[t] = c
			seenTarget[t] = true
		}
		if w.Built {
			m.Built++
		}
	}

	// The two lines above the grid.
	m.Phase = "SWEEPING"
	switch {
	case len(m.Building) > 0:
		m.Phase = "PHASE 1 BUILDING"
		m.Activity = "building " + strings.Join(m.Building, ", ")
	case len(running) > 0:
		var bits []string
		for ws, t := range running {
			bits = append(bits, ws+" "+Code(t))
		}
		sort.Strings(bits)
		m.Activity = "fuzzing " + strings.Join(bits, "   ")
	case DockerErr != "":
		// Said, not inferred. "Nothing is running" and "I cannot see whether
		// anything is running" are different statements, and only one of them
		// should be believed.
		m.Activity = "CANNOT SEE DOCKER -- " + DockerErr
	default:
		m.Activity = "idle -- no container running"
	}
	for _, w := range byWS {
		m.Rows = append(m.Rows, *w)
	}
	sort.Slice(m.Rows, func(i, j int) bool { return m.Rows[i].Name < m.Rows[j].Name })
	return m
}

// Elapsed is how long the campaign has been going.
// Elapsed stops when the campaign does.
//
// time.Since(Started) with no end climbs forever: a two-day-dead log once
// reported 76 hours elapsed, in the same field a live campaign uses. A
// campaign that is not running is measured to its last recorded slice.
func (m Model) Elapsed() time.Duration {
	// NO START, NO ELAPSED. The zero check guarded the second branch and not
	// the first, so a campaign with slices but no recorded start subtracted
	// from year one and the header read "elapsed 2562047h47m" -- a duration
	// clamped at its maximum, printed as if it were a measurement. It shows
	// up whenever live/campaign.json is missing, which is exactly the case
	// where a reader most needs to be told something is absent.
	if m.Started.IsZero() {
		return 0
	}
	if !m.Live && !m.LastSlice.IsZero() {
		return m.LastSlice.Sub(m.Started)
	}
	return time.Since(m.Started)
}

// Code is the two-letter column header for a target.
//
// Stable and derived, so a new target gets a heading without anybody editing a
// table -- a hand-maintained list is one that goes stale silently.
// Targets and their codes, EXPLICIT rather than derived.
//
// Derivation looked tidy and was wrong: taking the first letters of the first
// two words gives jsonb_fuzzer "js" and jsonpath_fuzzer "js" as well, so two
// columns carried the same label and the grid could not be read at all. These
// are the codes the old dashboard used, chosen by hand for exactly that reason.
//
// The list is also the DEFAULT COLUMN SET. A campaign knows its targets only
// once a build has finished, and without a fallback the grid has no columns at
// all during the build phase -- which is precisely when somebody is watching.
var codes = [][2]string{
	{"backend_types_fuzzer", "bt"}, {"binary_recv_fuzzer", "br"},
	{"config_file_fuzzer", "cf"}, {"conninfo_fuzzer", "ci"},
	{"datetime_fuzzer", "dt"}, {"encoding_fuzzer", "en"},
	{"extension_funcs_fuzzer", "ef"}, {"formatting_fuzzer", "fm"},
	{"geo_fuzzer", "ge"}, {"hba_file_fuzzer", "hb"},
	{"json_parser_fuzzer", "jp"}, {"jsonb_fuzzer", "jb"},
	{"jsonpath_fuzzer", "jx"}, {"network_fuzzer", "nw"},
	{"numeric_fuzzer", "nu"}, {"protocol_fuzzer", "pr"},
	{"raw_parser_fuzzer", "rp"}, {"regex_fuzzer", "rx"},
	{"scalar_types_fuzzer", "sc"}, {"simple_query_fuzzer", "sq"},
	{"spi_query_fuzzer", "sp"}, {"tsearch_fuzzer", "ts"},
	{"xlogreader_fuzzer", "xl"},
}

// DefaultTargets is the column set to draw before a build has said otherwise.
func DefaultTargets() []string {
	out := make([]string, 0, len(codes))
	for _, c := range codes {
		out = append(out, c[0])
	}
	return out
}

// Code is the two-letter column label for a target.
func Code(target string) string {
	for _, c := range codes {
		if c[0] == target {
			return c[1]
		}
	}
	// A target this build has and the table does not: derive something rather
	// than draw a blank column, and keep it two wide.
	n := strings.TrimSuffix(target, "_fuzzer")
	parts := strings.Split(n, "_")
	if len(parts) >= 2 {
		return string(parts[0][0]) + string(parts[1][0])
	}
	if len(n) >= 2 {
		return n[:2]
	}
	return n
}

// processAlive asks the kernel, not the filesystem.
//
// signal 0 is the standard "does this pid exist and may I signal it" probe.
// os.Signal(nil) is not that -- it typecheck but signals nothing and always
// returned nil, so a finished campaign reported itself as running. A marker
// file would be worse still: it outlives a kill -9.
// loadBreakdown reads crashes by component for the campaign's workspaces.
//
// From the same scan `pgfuzz breakdown` uses, so the dashboard and the command
// cannot disagree about where the crashes came from.
func loadBreakdown(wsRoot string, rows []Row, targets []string) []BreakdownRow {
	byComp := map[string]map[string]int{}
	for _, r := range rows {
		for comp, per := range breakdown.Scan(filepath.Join(wsRoot, r.Name), nil) {
			if byComp[comp] == nil {
				byComp[comp] = map[string]int{}
			}
			for t, n := range per {
				byComp[comp][t] += n
			}
		}
	}
	var out []BreakdownRow
	for comp, per := range byComp {
		row := BreakdownRow{Component: comp, PerTarget: per}
		for _, n := range per {
			row.Total += n
		}
		out = append(out, row)
	}
	SortBreakdown(out)
	return out
}

func processAlive(pid int) bool {
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return p.Signal(syscall.Signal(0)) == nil
}

// workspacesInSeries lists the workspaces of one campaign, in first-seen order.
//
// Through the cached read, because this is the SECOND full parse of the same
// file in the same frame: the dashboard read the series once for its rows and
// again here, once a second, for the whole length of a campaign.
func workspacesInSeries(path, slug string) []string {
	rows, err := (campaign.Series{Path: path}).ReadCached()
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, r := range rows {
		if r.Workspace == "" || seen[r.Workspace] ||
			!strings.HasPrefix(r.Workspace, slug) {
			continue
		}
		seen[r.Workspace] = true
		out = append(out, r.Workspace)
	}
	return out
}

// commitFor is the commit the grid shows for a workspace.
//
// THE ORIOLEDB COMMIT WINS WHERE THERE IS ONE, as it did before the port: for
// an OrioleDB workspace the PostgreSQL sha says which base the engine was
// built against, not which engine, and the engine is what the run is testing.
//
// The placeholder guard runs BEFORE the preference, not after. An older driver
// wrote `orioledb_sha=(not built)` into nine workspaces, and preferring the
// field without checking it first is exactly how that string took the column
// and rendered as "(not bui".
func commitFor(pgSHA, orioleSHA string) string {
	if odb := short10(orioleSHA); odb != "" {
		return odb
	}
	return short10(pgSHA)
}

// short10 trims a commit to what the grid shows, and rejects placeholders.
//
// An older driver wrote `orioledb_sha=(not built)` into nine workspaces on
// disk, and since the display preferred that field it displaced the real
// commit and rendered as "(not bui".
func short10(v string) string {
	for _, c := range v {
		if !strings.ContainsRune("0123456789abcdef", c) {
			return ""
		}
	}
	if len(v) > 10 {
		return v[:10]
	}
	return v
}

// declared reads the workspaces a campaign said it would run.
//
// Written before the build phase, so the grid can show a row for a workspace
// that has not produced anything yet -- which is the whole build phase.
func declared(dir string) []string {
	b, err := os.ReadFile(filepath.Join(dir, "live", "entries"))
	if err != nil {
		return nil
	}
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

// Package campaign runs many workspaces for many rounds, and records what
// happened in a form later tools can read.
//
// THE SERIES FILES ARE THE MODEL
// ==============================
// Not a document written at the end. Append-only JSONL rows, one per slice,
// with an index over them. Three properties follow, and all three matter here:
//
//   - append-only is what lets the ratchet compare a floor against history,
//     and what makes eighteen workspaces sweeping at once safe without a lock
//   - the index is derived, so it can never become the authority: a stale
//     index is a performance problem, a corrupt document is data loss
//   - a campaign killed mid-round leaves valid rows up to the kill, and
//     campaigns here are killed mid-round routinely
//
// THE DEADLINE IS A POLICY, NOT AN ACCIDENT
// =========================================
// A deadline is a promise about when the machine is free again; a round is the
// unit that gets compared. They conflict when the clock lands mid-sweep, and
// there is no answer right for every campaign -- so it is stated. Capped in
// every case: finish-round across eighteen workspaces is eighteen sweeps, and
// without a ceiling "eleven hours" could mean twenty.
package campaign

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// OnDeadline is what happens when the clock lands mid-sweep.
type OnDeadline string

const (
	Cut         OnDeadline = "cut"          // stop where you are; the round is short
	FinishSweep OnDeadline = "finish-sweep" // let the workspace in flight finish
	FinishRound OnDeadline = "finish-round" // finish the round, capped
)

// State is live/campaign.json: what is running, written when it commits to it.
type State struct {
	Slug    string `json:"slug"`
	RunID   string `json:"run_id"`
	PID     int    `json:"pid"`
	Started string `json:"started"`
	Driver  string `json:"driver"`
	Hours   string `json:"hours"`
}

// Slice is one row of the series: one target, one workspace, one round.
type Slice struct {
	RunID     string `json:"run_id"`
	Round     int    `json:"round"`
	Workspace string `json:"ws"`
	Target    string `json:"target"`
	Started   string `json:"started"`
	Seconds   int    `json:"secs"`
	Jobs      int    `json:"jobs"`
	// Dict is whether this slice ran with a dictionary. Structured formats
	// saturate fast without one, so its absence is a fact about the run.
	Dict     bool `json:"dict"`
	Execs    int  `json:"execs"`
	NewUnits int  `json:"new_units"`
	Cov      int  `json:"cov"`
	Ft       int  `json:"ft"`
	// Corpus after the slice, and before it. Both, for the same reason the
	// artifacts carry both: the funnel asks what this slice ADDED, and a
	// single total cannot answer that.
	Corpus       int `json:"corpus"`
	CorpusBefore int `json:"corpus_before"`

	// DiskStop marks a slice the disk floor cut short.
	//
	// It has to be in the record. Such a slice produced fewer executions for
	// a reason that has nothing to do with the target, and a ratchet
	// comparing it against a full one would call that a regression -- the
	// gate crying wolf about the filesystem.
	DiskStop bool `json:"disk_stop,omitempty"`

	// Hung marks a slice stopped for running past its own budget.
	//
	// Unlike DiskStop this is evidence ABOUT THE TARGET -- one input that
	// never returned -- so it does not disqualify the round from being
	// judged. It is recorded because a hang is a finding, and a slice that
	// produced few executions because it was stuck on one input is a
	// different fact from one that was simply slow.
	Hung bool `json:"hung,omitempty"`

	// PeakRSS is the highest resident size libFuzzer reported, in MB.
	//
	// PARSED SINCE THIS PACKAGE WAS WRITTEN AND CONSUMED BY NOTHING. It is
	// the only memory signal a slice produces, and the one that distinguishes
	// a target growing toward an OOM kill from one that is merely slow -- a
	// distinction that otherwise arrives as a dead container with no
	// explanation. Recorded so the trend is visible across slices rather than
	// only in the log of the slice that died.
	PeakRSS int `json:"peak_rss_mb,omitempty"`
	// Artifacts is what THIS slice produced. The before/after pair is kept
	// beside it so the total is still recoverable and the delta is never
	// re-derived by subtracting two numbers a reader had to find.
	Artifacts       int `json:"artifacts"`
	ArtifactsBefore int `json:"artifacts_before"`
	ArtifactsAfter  int `json:"artifacts_after"`
	Slowest         int `json:"slowest_unit_s"`

	// WHAT THE SLICE GAINED, as against what it reached.
	//
	// Peak coverage is mostly a property of the corpus the slice started
	// from: replay 300,000 saved inputs and the ceiling is reached before the
	// fuzzer has done anything. Only the delta says whether this slice did
	// work, and only SaturatedPct says whether another one would.
	CovStart      int      `json:"cov_start,omitempty"`
	FtStart       int      `json:"ft_start,omitempty"`
	CovGained     int      `json:"cov_gained_in_run"`
	FtGained      int      `json:"ft_gained_in_run"`
	LastNewEdgeAt int      `json:"last_new_edge_at,omitempty"`
	LastExecSeen  int      `json:"last_exec_seen,omitempty"`
	SaturatedPct  *float64 `json:"saturated_pct"`
	Alive         bool     `json:"alive"`
}

// Live is the directory a running campaign publishes itself in.
type Live struct{ Dir string }

// Open creates campaigns/<slug>/live and writes the state.
//
// Both drivers write this file, which is what lets a status tool find a
// campaign without guessing: pgrep on a script name knew about one driver and
// reported "no soak running" through a ten-hour matrix run.
func Open(root, slug string, st State) (Live, error) {
	dir := filepath.Join(root, slug, "live")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return Live{}, err
	}
	l := Live{Dir: dir}
	b, err := json.Marshal(st)
	if err != nil {
		return Live{}, err
	}
	if err := os.WriteFile(filepath.Join(dir, "campaign.json"), append(b, '\n'), 0o644); err != nil {
		return Live{}, err
	}
	return l, nil
}

// Entries records the workspaces this campaign covers.
//
// A file, not the command line: the driver takes no workspace arguments, so a
// status tool reading /proc/<pid>/cmdline finds none -- and reported "(no
// active workspace identified)" with eighteen of them running.
func (l Live) Entries(names []string) error {
	f, err := os.Create(filepath.Join(l.Dir, "entries"))
	if err != nil {
		return err
	}
	defer f.Close()
	for _, n := range names {
		fmt.Fprintln(f, n)
	}
	return nil
}

// Close removes the running marker.
func (l Live) Close() { os.Remove(filepath.Join(l.Dir, "running")) }

// MarkRunning writes the marker that says a driver is alive.
func (l Live) MarkRunning() error {
	return os.WriteFile(filepath.Join(l.Dir, "running"), []byte("1\n"), 0o644)
}

// Series appends slices to the campaign's record.
type Series struct{ Path string }

// Append writes one row.
//
// One row per slice, flushed immediately. A buffered writer loses the tail
// when the campaign is killed, and the tail is the part that says what was
// happening when it died.
// seriesMu serialises appends now that workspaces sweep concurrently.
//
// O_APPEND makes a single small write atomic on Linux, so rows would not
// interleave -- but relying on that is relying on the row staying under a
// pipe buffer forever, and a row grew every time a field was added to it.
// The lock costs nothing at one write per slice.
var seriesMu sync.Mutex

func (s Series) Append(sl Slice) error {
	seriesMu.Lock()
	defer seriesMu.Unlock()

	if err := os.MkdirAll(filepath.Dir(s.Path), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(s.Path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	b, err := json.Marshal(sl)
	if err != nil {
		return err
	}
	_, err = f.Write(append(b, '\n'))
	return err
}

// Read returns every slice recorded, skipping rows that do not parse.
//
// A single corrupt line -- a half-written row from a kill -- must not make the
// whole history unreadable, which is the main practical argument for JSONL
// over one document.
func (s Series) Read() ([]Slice, error) {
	b, err := os.ReadFile(s.Path)
	if err != nil {
		return nil, err
	}
	var out []Slice
	for _, line := range splitLines(b) {
		if len(line) == 0 {
			continue
		}
		var sl Slice
		if json.Unmarshal(line, &sl) == nil {
			out = append(out, sl)
		}
	}
	return out, nil
}

func splitLines(b []byte) [][]byte {
	var out [][]byte
	start := 0
	for i, c := range b {
		if c == '\n' {
			out = append(out, b[start:i])
			start = i + 1
		}
	}
	if start < len(b) {
		out = append(out, b[start:])
	}
	return out
}

// RunID is the identifier every row of one campaign shares.
func RunID(driver string, t time.Time) string {
	return driver + "-" + t.UTC().Format("20060102T150405Z")
}

// openAppend is used by the tests to simulate a truncated write.
func openAppend(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
}

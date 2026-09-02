package corpus

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Bounding every target's corpus so seed replay cannot eat its whole budget.
//
// THE FAILURE THIS PREVENTS
// =========================
// libFuzzer replays the entire seed corpus before it mutates anything. For a
// slow target the corpus can grow until replay alone outlasts -max_total_time:
// the run finishes without mutating once, adds nothing, and reports a large
// execution count -- so it looks like the busiest target on the grid while
// doing no fuzzing at all.
//
// The cap bounds replay COST. The per-target budget is its dual: a uniform
// budget assumes every target is equally worth time, which is false by two
// orders of magnitude -- measured over four rounds, spi_query averaged 11,081
// new inputs a round and conninfo_fuzzer averaged 18.

// AutocapOptions tunes the decision.
type AutocapOptions struct {
	// Fraction is the share of the budget replay may consume.
	Fraction float64
	// WarnFraction acts BEFORE a target locks. Locked is a late signal -- by
	// then the target has already lost a round. Deliberately higher than
	// Fraction: capping everything above a third would cut healthy productive
	// targets (raw_parser sits at 44% and adds thousands of units a round) to
	// buy headroom they do not need.
	WarnFraction float64
	Floor        int  // never cap below this many inputs
	All          bool // consider every target, however small its replay
	Skip         map[string]bool
}

// DefaultAutocap is what the campaign ran with.
func DefaultAutocap() AutocapOptions {
	return AutocapOptions{Fraction: 0.33, WarnFraction: 0.66, Floor: 500}
}

// TargetLog is what one target's section of a sweep log says.
type TargetLog struct {
	Budget     int
	Files      int
	Inited     *int
	Done       *int
	ReplayRate int
	Rate       int
	NewUnits   int
}

// Locked reports the state the cap exists to prevent: replay consumed the
// whole slice, so the run finished where it started.
func (t TargetLog) Locked() bool {
	return t.Inited != nil && t.Done != nil && *t.Inited == *t.Done
}

var (
	reBanner   = regexp.MustCompile(`^-+ ([a-z0-9_]+_fuzzer) -+$`)
	reAnsiCap  = regexp.MustCompile(`\x1b\[[0-9;]*m`)
	reMaxTotal = regexp.MustCompile(`max_total_time=(\d+)`)
	reFiles    = regexp.MustCompile(`(\d+) files found`)
	reHash     = regexp.MustCompile(`#(\d+)`)
	reDoneCap  = regexp.MustCompile(`#\d+\s+DONE`)
	reExecS    = regexp.MustCompile(`exec/s:\s*(\d+)`)
	reTrailNum = regexp.MustCompile(`(\d+)\s*$`)
)

// ParseSweepForCap reads one sweep log into per-target replay facts.
//
// Takes the FIRST job's numbers for inited/done/rate: with -jobs=N each job
// replays the same corpus, so they agree, and summing them would answer a
// different question than "how long does one replay take".
func ParseSweepForCap(path string) (map[string]*TargetLog, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var r io.Reader = f
	if strings.HasSuffix(path, ".gz") {
		zr, err := gzip.NewReader(f)
		if err != nil {
			return nil, err
		}
		defer zr.Close()
		r = zr
	}

	out := map[string]*TargetLog{}
	var cur *TargetLog
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 256*1024), 8*1024*1024)
	for sc.Scan() {
		raw := sc.Bytes()
		if !bytes.Contains(raw, []byte("_fuzzer -")) &&
			!bytes.Contains(raw, []byte("max_total_time=")) &&
			!bytes.Contains(raw, []byte("files found in")) &&
			!bytes.Contains(raw, []byte("INITED")) &&
			!bytes.Contains(raw, []byte("DONE")) &&
			!bytes.Contains(raw, []byte("new_units_added")) &&
			!bytes.Contains(raw, []byte("average_exec_per_sec")) {
			continue
		}
		line := reAnsiCap.ReplaceAllString(strings.TrimRight(sc.Text(), "\r"), "")
		if m := reBanner.FindStringSubmatch(strings.TrimSpace(line)); m != nil {
			if out[m[1]] == nil {
				out[m[1]] = &TargetLog{}
			}
			cur = out[m[1]]
			continue
		}
		if cur == nil {
			continue
		}
		switch {
		case strings.Contains(line, "max_total_time=") && cur.Budget == 0:
			if m := reMaxTotal.FindStringSubmatch(line); m != nil {
				cur.Budget, _ = strconv.Atoi(m[1])
			}
		case strings.Contains(line, "files found in") && cur.Files == 0:
			if m := reFiles.FindStringSubmatch(line); m != nil {
				cur.Files, _ = strconv.Atoi(m[1])
			}
		case strings.Contains(line, "INITED") && cur.Inited == nil:
			if m := reHash.FindStringSubmatch(line); m != nil {
				v, _ := strconv.Atoi(m[1])
				cur.Inited = &v
			}
			// The exec/s ON THIS LINE is the REPLAY rate, and it is the only
			// honest input to a replay-time prediction.
			//
			// average_exec_per_sec covers the whole run, and mutation is far
			// faster than replay because replay pays file I/O per input.
			// Measured on spi_query round 41: 130/s at INITED against 400/s
			// averaged -- 3x. Using the average made the cap 3x too
			// permissive, so the corpus was allowed to grow to about triple
			// what fits in the budget, which GUARANTEED the next round locked.
			if m := reExecS.FindStringSubmatch(line); m != nil {
				cur.ReplayRate, _ = strconv.Atoi(m[1])
			}
		case reDoneCap.MatchString(line) && cur.Done == nil:
			if m := reHash.FindStringSubmatch(line); m != nil {
				v, _ := strconv.Atoi(m[1])
				cur.Done = &v
			}
		case strings.Contains(line, "new_units_added"):
			if m := reTrailNum.FindStringSubmatch(line); m != nil {
				n, _ := strconv.Atoi(m[1])
				cur.NewUnits += n
			}
		case strings.Contains(line, "average_exec_per_sec") && cur.Rate == 0:
			if m := reTrailNum.FindStringSubmatch(line); m != nil {
				cur.Rate, _ = strconv.Atoi(m[1])
			}
		}
	}
	return out, sc.Err()
}

// CapDecision is what autocap concluded for one target.
type CapDecision struct {
	Target        string
	Files         int
	Rate          int
	ReplaySeconds float64
	Budget        int
	Cap           int
	Live          int
	Locked        bool
	AtRisk        bool
	Act           bool
}

// State renders the decision the way the report reads it.
func (d CapDecision) State() string {
	s := "ok"
	switch {
	case d.Locked:
		s = "LOCKED"
	case d.AtRisk:
		s = "at-risk"
	}
	if d.Act {
		s += fmt.Sprintf(": %d -> %d", d.Live, d.Cap)
	}
	return s
}

// Autocap decides, for every target in the log, whether its corpus must be
// bounded.
func Autocap(wsDir string, per map[string]*TargetLog, o AutocapOptions) []CapDecision {
	var ts []string
	for t := range per {
		ts = append(ts, t)
	}
	sort.Strings(ts)

	var out []CapDecision
	for _, t := range ts {
		if o.Skip[t] {
			continue
		}
		d := per[t]
		// Prefer the replay rate; fall back to the average only if the INITED
		// line carried no exec/s -- which is what a locked round looks like,
		// and there the two are the same number anyway.
		rate := d.ReplayRate
		if rate == 0 {
			rate = d.Rate
		}
		if d.Files == 0 || rate == 0 || d.Budget == 0 {
			continue
		}
		dec := CapDecision{
			Target: t, Files: d.Files, Rate: rate, Budget: d.Budget,
			ReplaySeconds: float64(d.Files) / float64(rate),
			Locked:        d.Locked(),
			Live:          countFiles(filepath.Join(wsDir, "corpus", t)),
		}
		dec.AtRisk = dec.ReplaySeconds > o.WarnFraction*float64(d.Budget)
		dec.Cap = int(o.Fraction * float64(d.Budget) * float64(rate))
		if dec.Cap < o.Floor {
			dec.Cap = o.Floor
		}
		// Only act when the corpus actually EXCEEDS the derived cap. A locked
		// target whose cap already exceeds its corpus is locked for some other
		// reason, and silently shrinking it would hide that.
		dec.Act = (dec.Locked || dec.AtRisk || o.All) && dec.Live > dec.Cap
		out = append(out, dec)
	}
	return out
}

// Budgets are the per-target time allocations, keyed by workspace and target.
type Budgets map[[2]string]int

// ReadBudgets loads the tsv.
func ReadBudgets(path string) Budgets {
	out := Budgets{}
	b, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) != 3 {
			continue
		}
		if v, err := strconv.Atoi(f[2]); err == nil {
			out[[2]string{f[0], f[1]}] = v
		}
	}
	return out
}

// Write saves the budgets atomically.
func (b Budgets) Write(path string) error {
	var keys [][2]string
	for k := range b {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i][0] != keys[j][0] {
			return keys[i][0] < keys[j][0]
		}
		return keys[i][1] < keys[j][1]
	})
	var sb strings.Builder
	sb.WriteString("# workspace\ttarget\tseconds -- maintained by `pgfuzz corpus -autocap -tune-budget`\n")
	for _, k := range keys {
		fmt.Fprintf(&sb, "%s\t%s\t%d\n", k[0], k[1], b[k])
	}
	tmp := fmt.Sprintf("%s.%d.tmp", path, os.Getpid())
	if err := os.WriteFile(tmp, []byte(sb.String()), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// BudgetChange is one target's adjusted allocation.
type BudgetChange struct {
	Target    string
	Was, Want int
	Found     int
}

// TuneOptions bounds the adjustment.
type TuneOptions struct {
	High, Low             int
	BaseBudget, MaxBudget int
}

// DefaultTune is what the campaign ran with.
func DefaultTune() TuneOptions {
	return TuneOptions{High: 2000, Low: 200, BaseBudget: 90, MaxBudget: 600}
}

// Tune moves each target's budget toward what its discovery rate justifies.
//
// Hysteresis -- raise 1.5x, lower 1.5x, with a dead band between the
// thresholds -- so a target that straddles a threshold does not oscillate.
func Tune(ws string, per map[string]*TargetLog, cur Budgets, o TuneOptions) []BudgetChange {
	var ts []string
	for t := range per {
		ts = append(ts, t)
	}
	sort.Strings(ts)

	var changed []BudgetChange
	for _, t := range ts {
		d := per[t]
		if d.Budget == 0 {
			continue
		}
		// A LOCKED round says nothing about how productive the target WOULD
		// be -- it never got to mutate. The cap deals with that; leave the
		// budget alone.
		if d.Locked() {
			continue
		}
		have, ok := cur[[2]string{ws, t}]
		if !ok {
			have = d.Budget
		}
		want := have
		switch {
		case d.NewUnits >= o.High:
			want = min(int(float64(have)*1.5), o.MaxBudget)
		case d.NewUnits < o.Low:
			want = max(int(float64(have)/1.5), o.BaseBudget)
		default:
			continue
		}
		if want != have {
			cur[[2]string{ws, t}] = want
			changed = append(changed, BudgetChange{t, have, want, d.NewUnits})
		}
	}
	return changed
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// RemovalRecord is one capped target's loss, recorded because a cap is
// MAINTENANCE and must not read as the corpus shrinking on its own.
//
// The growth check adds the cumulative total back before computing growth, so
// a round that caps 18,000 files does not look like a 2.5% collapse -- which
// would trip the shrank guard, reset the plateau counter, and do so again
// every round a capped target keeps working.
type RemovalRecord struct {
	WS      string `json:"ws"`
	Target  string `json:"target"`
	Removed int    `json:"removed"`
	When    string `json:"when"`
}

// RecordRemoval appends one line.
func RecordRemoval(path string, r RemovalRecord) error {
	if r.When == "" {
		r.When = time.Now().UTC().Format(time.RFC3339Nano)
	}
	raw, err := json.Marshal(r)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(append(raw, '\n'))
	return err
}

// IsCoverageWorkspace reports whether a workspace exists to MEASURE rather
// than to fuzz.
//
// NEVER CAP ONE. The cap exists because libFuzzer replays the whole corpus
// before it mutates, so on a slow target replay can eat the entire slice --
// that is a FUZZING problem, about a time budget shared with mutation.
//
// Coverage has no such budget. Its input set is bounded: every input is
// replayed once and the pass ends. A slow coverage run is slow, not stuck.
// Capping there would only remove inputs from the MEASUREMENT, making the
// coverage figure describe a subset of the corpus while the report presents it
// as the campaign's coverage.
func IsCoverageWorkspace(wsDir string) bool {
	b, err := os.ReadFile(filepath.Join(wsDir, "workspace.conf"))
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if v, ok := strings.CutPrefix(line, "sanitizer="); ok {
			return strings.TrimSpace(v) == "coverage"
		}
	}
	return false
}

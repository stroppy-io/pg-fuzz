package finalreport

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// How long a campaign ran, derived from the slice series.
//
// ONE IMPLEMENTATION, TWO REPORTS. Both generators need this and neither should
// own it: a figure computed twice is a figure that disagrees with itself
// eventually, and "how long did it run" is exactly the kind of number a reader
// compares between the summary and the detail.
//
// WHY RUNS ARE DETECTED RATHER THAN DECLARED
//
// Nothing records where one campaign ends and the next begins -- the series is
// a flat list of slices. But a slice runs for at least 900s and usually 1800s,
// so an hour in which no slice STARTED means nothing was running. Splitting on
// that gap recovers the boundaries from the data, and recovers them correctly:
// the last run comes out at 10.5h against a campaign launched with --hours 10
// that then drained a wedged target.
//
// WHY NOT FIRST-TO-LAST
//
// Because that counts the gaps between campaigns and the hours spent draining
// a wedged target. Both spans are returned so the difference is VISIBLE rather
// than asserted -- SpanHours against ActiveHours -- and neither is hardcoded,
// because the first attempt at this comparison quoted a figure from a broader
// query as though it described this campaign.

// RunGapMinutes: an hour with no slice STARTING means nothing was running.
// Slices are >= 900s and typically 1800s, so this cannot split a campaign that
// was merely slow.
const RunGapMinutes = 60

// Runtime is what the report says about elapsed and machine time.
type Runtime struct {
	Runs           int      `json:"runs"`
	RunSource      string   `json:"run_source"`
	Slices         int      `json:"slices"`
	SlicesTimed    int      `json:"slices_timed"`
	MachineHours   *float64 `json:"machine_hours"`
	ActiveHours    float64  `json:"active_hours"`
	LastRunHours   float64  `json:"last_run_hours"`
	LastRunSlices  int      `json:"last_run_slices"`
	LastRunStart   string   `json:"last_run_start"`
	LastRunEnd     string   `json:"last_run_end"`
	First          string   `json:"first"`
	Last           string   `json:"last"`
	Days           int      `json:"days"`
	SpanHours      float64  `json:"span_hours"`
	CoreHours      *float64 `json:"core_hours"`
	CPUHours       *float64 `json:"cpu_hours"`
	SlicesCPU      int      `json:"slices_cpu_sampled"`
	CPUUtilisation *float64 `json:"cpu_utilisation"`
	CoreHoursEst   *float64 `json:"core_hours_est"`
	CoreHoursBasis string   `json:"core_hours_basis"`
	OK             bool     `json:"-"`
}

type runtimeRow struct {
	WS       string   `json:"ws"`
	LogMTime string   `json:"log_mtime"`
	RunID    string   `json:"run_id"`
	Secs     *int     `json:"secs"`
	Jobs     *int     `json:"jobs"`
	CPUSecs  *float64 `json:"cpu_secs"`
	t        time.Time
}

// GatherRuntime reads the series and reconstructs the run boundaries.
func GatherRuntime(seriesPath, wsRoot, prefix string) Runtime {
	f, err := os.Open(seriesPath)
	if err != nil {
		return Runtime{}
	}
	defer f.Close()

	var rows []runtimeRow
	dec := json.NewDecoder(f)
	for {
		var r runtimeRow
		if err := dec.Decode(&r); err != nil {
			break
		}
		if r.LogMTime == "" || !strings.HasPrefix(r.WS, prefix) {
			continue
		}
		t, err := parseISO(r.LogMTime)
		if err != nil {
			continue
		}
		r.t = t
		rows = append(rows, r)
	}
	if len(rows) == 0 {
		return Runtime{}
	}
	// Sorted ON THE TIMESTAMP ONLY. Two rows with the same mtime must not fall
	// through to comparing the rows themselves.
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].t.Before(rows[j].t) })

	// PREFER THE RECORDED RUN ID over the gap heuristic. A campaign stamps
	// PGFUZZ_RUN_ID on every slice it launches, so once one has run under it
	// the boundaries are a fact rather than an inference. The gap rule stays
	// for rows written before that and for slices run by hand.
	//
	// MIXED IS THE NORMAL CASE, and it must not be handled by picking a side.
	// A first version switched entirely to id-mode as soon as ANY row carried
	// an id and bucketed the rest by date; with a single stamped row against
	// 1,495 unstamped ones that turned 8 runs into 7 -- the first slice of the
	// next campaign made the figure worse than the heuristic it replaced.
	var stamped, plain []runtimeRow
	for _, r := range rows {
		if r.RunID != "" {
			stamped = append(stamped, r)
		} else {
			plain = append(plain, r)
		}
	}

	var runs [][]runtimeRow
	var source string
	switch {
	case len(stamped) > 0 && len(plain) == 0:
		runs = groupByID(stamped)
		source = "recorded run ids"
	case len(stamped) > 0:
		byID := groupByID(stamped)
		gapRuns := groupByGap(plain)
		runs = append(gapRuns, byID...)
		source = fmt.Sprintf("%d run(s) from recorded ids, %d inferred from gaps",
			len(byID), len(gapRuns))
	default:
		runs = groupByGap(rows)
		source = fmt.Sprintf("inferred from gaps of more than %d minutes", RunGapMinutes)
	}

	spanH := func(run []runtimeRow) float64 {
		return hours(run[len(run)-1].t.Sub(run[0].t))
	}

	var secsTotal, coreS, nSecs int
	var burned float64
	var nBurned int
	for _, r := range rows {
		if r.Secs != nil && *r.Secs != 0 {
			secsTotal += *r.Secs
			nSecs++
			j := 1
			if r.Jobs != nil && *r.Jobs > 0 {
				j = *r.Jobs
			}
			// Core-time is seconds x WORKERS: a 1800s slice at -jobs=4 occupies
			// four cores, and summing seconds alone understates it fourfold.
			coreS += *r.Secs * j
		}
		if r.CPUSecs != nil && *r.CPUSecs != 0 {
			burned += *r.CPUSecs
			nBurned++
		}
	}

	days := map[string]bool{}
	for _, r := range rows {
		days[r.t.Format("2006-01-02")] = true
	}
	last := runs[len(runs)-1]
	var active float64
	for _, run := range runs {
		active += spanH(run)
	}

	out := Runtime{
		OK: true, Runs: len(runs), RunSource: source, Slices: len(rows),
		SlicesTimed: nSecs, ActiveHours: active,
		LastRunHours: spanH(last), LastRunSlices: len(last),
		LastRunStart: iso(last[0].t), LastRunEnd: iso(last[len(last)-1].t),
		First: iso(rows[0].t), Last: iso(rows[len(rows)-1].t),
		Days:      len(days),
		SpanHours: hours(rows[len(rows)-1].t.Sub(rows[0].t)),
		SlicesCPU: nBurned,
	}
	if nSecs > 0 {
		v := float64(secsTotal) / 3600
		out.MachineHours = &v
	}
	if coreS > 0 {
		v := float64(coreS) / 3600
		out.CoreHours = &v
	}
	if burned > 0 {
		v := burned / 3600
		out.CPUHours = &v
	}
	// What was actually burned, as against what was allocated. Only these two
	// together say anything useful: a slice that waits on a backend consumes a
	// fraction of the core it was given, and reporting the allocation as work
	// done overstates the quiet targets by more than an order of magnitude.
	if coreS > 0 && burned > 0 {
		v := burned / float64(coreS)
		out.CPUUtilisation = &v
	}
	est, basis := estimatedCoreHours(wsRoot, prefix, len(rows))
	out.CoreHoursEst, out.CoreHoursBasis = est, basis
	return out
}

func groupByID(rows []runtimeRow) [][]runtimeRow {
	byID := map[string][]runtimeRow{}
	var order []string
	for _, r := range rows {
		if _, ok := byID[r.RunID]; !ok {
			order = append(order, r.RunID)
		}
		byID[r.RunID] = append(byID[r.RunID], r)
	}
	out := make([][]runtimeRow, 0, len(order))
	for _, k := range order {
		out = append(out, byID[k])
	}
	return out
}

func groupByGap(rows []runtimeRow) [][]runtimeRow {
	if len(rows) == 0 {
		return nil
	}
	var out [][]runtimeRow
	cur := []runtimeRow{rows[0]}
	for i := 1; i < len(rows); i++ {
		if rows[i].t.Sub(rows[i-1].t).Minutes() > RunGapMinutes {
			out = append(out, cur)
			cur = []runtimeRow{rows[i]}
		} else {
			cur = append(cur, rows[i])
		}
	}
	return append(out, cur)
}

var (
	reBudget = regexp.MustCompile(`max_total_time=(\d+)`)
	reJobsRT = regexp.MustCompile(`-jobs=(\d+)`)
)

// estimatedCoreHours offers an estimate ONLY when the observed cost is uniform.
//
// Historical rows carry no budget, so the exact total covers only recent
// slices. The logs still on disk show what a slice costs, and if every one of
// them agrees the estimate is a multiplication rather than a guess. If they
// disagree, no estimate is returned at all: a mean over a mixed population
// would be the same class of number as a wall-clock span standing in for
// machine time.
func estimatedCoreHours(wsRoot, prefix string, nSlices int) (*float64, string) {
	budgets, jobs := map[int]bool{}, map[int]bool{}
	dirs, _ := filepath.Glob(filepath.Join(wsRoot, prefix+"*"))
	for _, d := range dirs {
		logs, _ := filepath.Glob(filepath.Join(d, "soak-*_fuzzer.log"))
		for _, p := range logs {
			f, err := os.Open(p)
			if err != nil {
				continue
			}
			// The invocation is in the head of the file; reading it all would
			// be gigabytes for one regex.
			buf := make([]byte, 200000)
			n, _ := f.Read(buf)
			f.Close()
			head := string(buf[:n])
			if m := reBudget.FindStringSubmatch(head); m != nil {
				v, _ := strconv.Atoi(m[1])
				budgets[v] = true
			}
			if m := reJobsRT.FindStringSubmatch(head); m != nil {
				v, _ := strconv.Atoi(m[1])
				jobs[v] = true
			} else {
				jobs[1] = true
			}
		}
	}
	if len(budgets) != 1 || len(jobs) != 1 {
		return nil, "slice cost varies across targets; no estimate"
	}
	var b, j int
	for k := range budgets {
		b = k
	}
	for k := range jobs {
		j = k
	}
	v := float64(nSlices*b*j) / 3600
	return &v, fmt.Sprintf("%s slices x %ds x %d worker(s), every observed slice log agreeing on both",
		commaI(nSlices), b, j)
}

func commaI(n int) string {
	s := strconv.Itoa(n)
	var out []byte
	for i := 0; i < len(s); i++ {
		if i > 0 && (len(s)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, s[i])
	}
	return string(out)
}

// parseISO accepts the timestamp shapes these files carry.
func parseISO(s string) (time.Time, error) {
	for _, layout := range []string{
		"2006-01-02T15:04:05.000000-07:00", time.RFC3339Nano, time.RFC3339,
		"2006-01-02T15:04:05",
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("unparseable timestamp %q", s)
}

// iso renders a timestamp the way the Python's isoformat() did, so the two
// reports quote the same string for the same instant.
func iso(t time.Time) string {
	s := t.Format("2006-01-02T15:04:05.000000-07:00")
	// isoformat() drops the fractional part when it is zero.
	return strings.Replace(s, ".000000", "", 1)
}

// hours converts a duration through WHOLE MICROSECONDS.
//
// These timestamps carry microsecond resolution, and the figure is quoted in
// two different reports that a reader compares. Dividing nanoseconds gives a
// last-bit difference from dividing microseconds, and two reports disagreeing
// in the sixteenth digit is the kind of thing that costs an hour to explain.
func hours(d time.Duration) float64 {
	return float64(d.Nanoseconds()/1000) / 1e6 / 3600
}

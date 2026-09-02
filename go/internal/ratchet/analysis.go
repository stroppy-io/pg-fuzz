package ratchet

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"sort"
	"strconv"
	"strings"
)

// The analyses that read the SERIES and the HISTORY rather than one round.
//
// These exist because the queries were run by hand first, and the FIRST one
// was wrong: it filtered on `when` and `workspace`, fields this tool has never
// written (they are `log_mtime` and `ws`), matched nothing, and reported "zero
// floors raised in nine hours" against a gate that had in fact raised 364.
//
// A hand-written query against someone else's JSON does not know the schema and
// fails silently when it guesses wrong -- and it fails toward "nothing is
// happening", which is the direction that gets believed. The tool knows its own
// field names. Ask it.

// SeriesRow is one workspace-round of observations.
type SeriesRow struct {
	WS       string         `json:"ws"`
	Round    *int           `json:"round"`
	LogMTime string         `json:"log_mtime"`
	Execs    map[string]int `json:"execs"`
}

// HistoryRow is one workspace-round that moved a floor.
type HistoryRow struct {
	WS       string `json:"ws"`
	Round    *int   `json:"round"`
	LogMTime string `json:"log_mtime"`
	Changes  []struct {
		Kind   string `json:"kind"`
		Target string `json:"target"`
		From   int    `json:"from"`
		To     int    `json:"to"`
	} `json:"changes"`
}

// ReadJSONL reads a series or history file, skipping lines that will not parse.
func ReadJSONL[T any](path string) []T {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []T
	dec := json.NewDecoder(f)
	for {
		var v T
		if err := dec.Decode(&v); err != nil {
			if err == io.EOF {
				break
			}
			// A malformed line is skipped, not fatal: the series is appended to
			// by every round and a truncated write must not blind the analysis.
			var skip json.RawMessage
			if dec.Decode(&skip) != nil {
				break
			}
			continue
		}
		out = append(out, v)
	}
	return out
}

// sinceOK compares an ISO timestamp by PREFIX, not by parsing, so both
// "2026-08-22" and "2026-08-22T23:5" work and neither needs a timezone.
func sinceOK(mtime, since string) bool { return since == "" || mtime >= since }

func span(ts []string) (string, string) {
	var got []string
	for _, t := range ts {
		if t != "" {
			got = append(got, t)
		}
	}
	if len(got) == 0 {
		return "?", "?"
	}
	sort.Strings(got)
	return cut16(got[0]), cut16(got[len(got)-1])
}

func cut16(s string) string {
	if len(s) > 16 {
		return s[:16]
	}
	return s
}

// Show prints the baseline, highest floor first within each workspace.
func Show(w io.Writer, b Baseline, only string) {
	fmt.Fprintf(w, "tolerance: %d%% of floor\n", int(b.Tol()*100))
	var wss []string
	for ws := range b.Floors {
		if only == "" || ws == only {
			wss = append(wss, ws)
		}
	}
	if only != "" && len(wss) == 0 {
		wss = []string{only} // a workspace with no floors is still reported
	}
	sort.Strings(wss)
	for _, ws := range wss {
		fmt.Fprintf(w, "\n%s\n", ws)
		fl := b.Floors[ws]
		ts := make([]string, 0, len(fl))
		for t := range fl {
			ts = append(ts, t)
		}
		sort.Slice(ts, func(i, j int) bool {
			if fl[ts[i]] != fl[ts[j]] {
				return fl[ts[i]] > fl[ts[j]]
			}
			return ts[i] < ts[j]
		})
		for _, t := range ts {
			fmt.Fprintf(w, "  %12s  %s\n", commaInt(fl[t]), t)
		}
	}
}

// CUSUM parameters. Overridable because the right values depend on how long a
// slice is, and a slice length is configuration.
type CusumOptions struct {
	K, H, Clip float64
	MinRounds  int
}

// DefaultCusum is what the campaign ran with.
func DefaultCusum() CusumOptions {
	return CusumOptions{K: 0.5, H: 4.0, Clip: 3.0, MinRounds: 8}
}

// Cusum detects a persistent downward SHIFT, which the record's skirt sleeps
// through.
//
// The monotone record answers "is this round catastrophically below the best
// ever?" with a deliberately loose 10% line. That line is set where it is
// because round-to-round noise is genuinely large, and it means a target can
// lose 85% of its throughput and pass forever.
//
// CUSUM answers the other question: has the level shifted DOWN and STAYED
// down. Small deviations accumulate instead of being forgiven one round at a
// time, so a persistent 50% loss trips it within a few rounds even though no
// single round is anywhere near the 10% line.
//
// Three deliberate choices:
//
//	log space   Throughput is multiplicative -- a target does half as much,
//	            not 200,000 fewer -- so a shift is a constant in log space
//	            regardless of whether the pair runs at 128 or 20 million. One
//	            set of parameters then fits all 733 pairs.
//
//	robust      median and MAD, not mean and standard deviation. The tail is
//	            the signal here; a classical estimator would let the outliers
//	            inflate the threshold that is meant to catch them.
//
//	one-sided   Only drops. A target getting faster is not an incident, and a
//	            two-sided chart would spend half its sensitivity on good news.
//
// NOT a Kalman filter, deliberately. Kalman TRACKS: it updates its estimate
// toward what it sees, so a target degrading steadily would drag the estimate
// down with it and keep reporting nominal -- the exact erosion the monotone
// record exists to prevent. CUSUM measures against a fixed reference and
// accumulates, so a sustained shift keeps adding up instead of becoming the
// new normal.
func Cusum(w io.Writer, rows []SeriesRow, workspaces []string, o CusumOptions) int {
	if len(workspaces) == 0 {
		seen := map[string]bool{}
		for _, r := range rows {
			if !seen[r.WS] {
				seen[r.WS] = true
				workspaces = append(workspaces, r.WS)
			}
		}
		sort.Strings(workspaces)
	}
	if len(workspaces) == 0 {
		fmt.Fprintln(w, "no series recorded yet -- run `pgfuzz ratchet -update` over some rounds first")
		return 2
	}

	bad := 0
	for _, ws := range workspaces {
		var rounds []SeriesRow
		for _, r := range rows {
			if r.WS == ws {
				rounds = append(rounds, r)
			}
		}
		fmt.Fprintf(w, "\n== cusum: %s\n", ws)
		fmt.Fprintf(w, "  %d round(s) recorded   k=%s h=%s min-rounds=%d\n",
			len(rounds), pyFloat(o.K), pyFloat(o.H), o.MinRounds)
		// Training window plus at least one round to judge against it.
		need := o.MinRounds + 1
		if len(rounds) < need {
			fmt.Fprintf(w, "  insufficient history -- need %d (%d to train on, 1 to judge), have %d.\n",
				need, o.MinRounds, len(rounds))
			// Not a pass. Nothing was checked, and silence about that is how
			// an unchecked target reads as a healthy one.
			fmt.Fprintln(w, "  this is not a pass -- nothing was checked.")
			continue
		}

		seen := map[string]bool{}
		var targets []string
		for _, r := range rounds {
			for t := range r.Execs {
				if !seen[t] {
					seen[t] = true
					targets = append(targets, t)
				}
			}
		}
		sort.Strings(targets)

		for _, t := range targets {
			var xs []int
			for _, r := range rounds {
				if v, ok := r.Execs[t]; ok {
					xs = append(xs, v)
				}
			}
			if len(xs) < o.MinRounds+1 {
				continue
			}
			lg := make([]float64, len(xs))
			for i, x := range xs {
				lg[i] = math.Log(math.Max(float64(x), 1)) // guard a dead target's zero
			}

			// Phase I / Phase II. The reference comes from a TRAINING WINDOW,
			// not from the whole series.
			//
			// This is not a refinement, it is the difference between working
			// and not. Estimating the median and MAD over every point includes
			// the shift being looked for: the median slides toward the new
			// level and the MAD is inflated by the step itself, so the
			// detector raises its own threshold in proportion to the size of
			// the event it exists to catch. The bigger the regression, the
			// harder it becomes to see -- the worst possible failure direction.
			train := lg[:o.MinRounds]
			med := median(train)
			sd := mad(train, med)
			if sd <= 0 {
				// A perfectly flat training window has no scale. Fall back to
				// a floor rather than dividing by zero -- 10% of the level, in
				// log terms, is a deliberately blunt stand-in.
				sd = 0.10
			}
			S, tripAt := 0.0, -1
			for i := o.MinRounds; i < len(lg); i++ {
				z := (lg[i] - med) / sd
				// Clip only the downside; an improvement may pull S down as
				// far as it likes, because forgetting good news fast is fine
				// and forgetting bad news fast is not.
				z = math.Max(z, -o.Clip)
				S = math.Max(0, S-z-o.K)
				if S > o.H && tripAt < 0 {
					tripAt = i
				}
			}
			if tripAt >= 0 {
				fmt.Fprintf(w, "  SHIFT %s: S=%.1f > %s (first tripped at round index %d, %s execs; median %s)\n",
					t, S, pyFloat(o.H), tripAt, commaInt(xs[tripAt]), commaInt(int(math.Exp(med))))
				bad++
			}
		}
	}

	fmt.Fprintf(w, "\n== result\n")
	if bad > 0 {
		fmt.Fprintf(w, "  %d target(s) shifted down and stayed down\n", bad)
		return 1
	}
	fmt.Fprintln(w, "  no sustained downward shift")
	return 0
}

// Activity reports what the floors DID -- the upward half of the ratchet,
// which is invisible in a pass/fail line.
//
// A gate that only ever reports failures cannot be distinguished from a gate
// that is not running. This is the evidence that it is.
func Activity(w io.Writer, all []HistoryRow, since string, top int) int {
	var recs []HistoryRow
	var mts []string
	for _, r := range all {
		if sinceOK(r.LogMTime, since) {
			recs = append(recs, r)
			mts = append(mts, r.LogMTime)
		}
	}
	if len(recs) == 0 {
		fmt.Fprintf(w, "  no history records%s\n", sinceNote(since))
		return 0
	}
	lo, hi := span(mts)

	kinds := map[string]int{}
	for _, r := range recs {
		for _, c := range r.Changes {
			kinds[c.Kind]++
		}
	}
	fmt.Fprintf(w, "\n== ratchet activity   %s -> %s\n", lo, hi)
	fmt.Fprintf(w, "  %d workspace-round(s) moved a floor\n", len(recs))
	for _, k := range byCountDesc(kinds) {
		fmt.Fprintf(w, "    %6d  %s\n", kinds[k], k)
	}

	byRound := map[int]map[string]bool{}
	noRound := map[string]bool{}
	for _, r := range recs {
		if r.Round == nil {
			noRound[r.WS] = true
			continue
		}
		if byRound[*r.Round] == nil {
			byRound[*r.Round] = map[string]bool{}
		}
		byRound[*r.Round][r.WS] = true
	}
	var rs []int
	for k := range byRound {
		rs = append(rs, k)
	}
	sort.Ints(rs)
	fmt.Fprintln(w)
	for _, k := range rs {
		fmt.Fprintf(w, "    round %d: %d workspace(s)\n", k, len(byRound[k]))
	}
	if len(noRound) > 0 {
		fmt.Fprintf(w, "    round None: %d workspace(s)\n", len(noRound))
	}

	type raise struct {
		Ratio      float64
		WS, Target string
		From, To   int
	}
	var raises []raise
	for _, r := range recs {
		for _, c := range r.Changes {
			if c.Kind == "raise" && c.From != 0 {
				raises = append(raises, raise{
					float64(c.To) / math.Max(float64(c.From), 1), r.WS, c.Target, c.From, c.To})
			}
		}
	}
	sort.Slice(raises, func(i, j int) bool { return raises[i].Ratio > raises[j].Ratio })
	if len(raises) > 0 {
		fmt.Fprintf(w, "\n== largest raises (top %d)\n", top)
		// A floor jumping by orders of magnitude is usually not the target
		// improving -- it is a floor recorded while something was broken,
		// being repaired.
		fmt.Fprintln(w, "  A floor jumping by orders of magnitude is usually not the target")
		fmt.Fprintln(w, "  improving -- it is a floor that was recorded while something was")
		fmt.Fprintln(w, "  broken, being repaired. Read the biggest ones that way first.")
		fmt.Fprintln(w)
		for i, x := range raises {
			if i >= top {
				break
			}
			fmt.Fprintf(w, "  x%9s  %-18s %-24s %13s -> %13s\n",
				commaFloat1(x.Ratio), x.WS, x.Target, commaInt(x.From), commaInt(x.To))
		}
	}
	return 0
}

// The histogram edges. Deliberately finer below the tolerance than above it:
// the question this answers is whether the tolerance sits in a GAP or in a
// continuum, and that is only visible if the buckets near it are narrow.
var (
	distEdges  = []float64{0, .01, .05, .10, .25, .50, .75, .90, 1.0, math.Inf(1)}
	distLabels = []string{"<1%", "1-5%", "5-10%", "10-25%", "25-50%",
		"50-75%", "75-90%", "90-100%", ">=100%"}
)

// Distribution shows where observations sit relative to their floors.
//
// The tolerance was chosen to sit below the worst honest round and above the
// noise. That is a claim about a distribution, and it stops being true when
// the hardware, the corpus or the harness changes -- so it is worth re-reading
// rather than re-asserting. If the buckets either side of the line are both
// populated, the tolerance is cutting a continuum and a different number would
// change verdicts; say so rather than reading a low failure rate as proof the
// threshold was right.
func Distribution(w io.Writer, b Baseline, all []SeriesRow, acks map[string]string, since string) int {
	var recs []SeriesRow
	var mts []string
	for _, r := range all {
		if sinceOK(r.LogMTime, since) {
			recs = append(recs, r)
			mts = append(mts, r.LogMTime)
		}
	}
	if len(recs) == 0 {
		fmt.Fprintf(w, "  no observations%s\n", sinceNote(since))
		return 0
	}
	tol := b.Tol()

	type rat struct {
		R          float64
		WS, Target string
		V, F       int
	}
	var rats []rat
	for _, o := range recs {
		fl := b.Floors[o.WS]
		for t, v := range o.Execs {
			if f, ok := fl[t]; ok && f > 0 {
				rats = append(rats, rat{float64(v) / float64(f), o.WS, t, v, f})
			}
		}
	}
	if len(rats) == 0 {
		fmt.Fprintln(w, "  observations exist but none has a floor to compare against")
		return 0
	}

	lo, hi := span(mts)
	counts := make([]int, len(distLabels))
	for _, r := range rats {
		for i := 0; i < len(distEdges)-1; i++ {
			if distEdges[i] <= r.R && r.R < distEdges[i+1] {
				counts[i]++
				break
			}
		}
	}
	fmt.Fprintf(w, "\n== observed / best-ever floor   %s -> %s\n", lo, hi)
	fmt.Fprintf(w, "  %d workspace-round(s), %d target observation(s) with a floor\n",
		len(recs), len(rats))
	fmt.Fprintf(w, "  the gate fires below %d%% of floor\n\n", int(tol*100))

	mx := 1
	for _, c := range counts {
		if c > mx {
			mx = c
		}
	}
	for i, lab := range distLabels {
		mark := ""
		if distEdges[i+1] <= tol {
			mark = "  <-- fails"
		}
		fmt.Fprintf(w, "  %9s  %6d  %s%s\n", lab, counts[i],
			strings.Repeat("#", counts[i]*50/mx), mark)
	}

	nBelow := 0
	for i, c := range counts {
		if distEdges[i+1] <= tol {
			nBelow += c
		}
	}
	// The bucket immediately above the line: if it is populated, the line is
	// in a continuum, not a gap.
	aboveI := 0
	for i := range distLabels {
		if distEdges[i] >= tol {
			aboveI = i
			break
		}
	}
	fmt.Fprintf(w, "\n  below the line: %d   in %s, the band just above it: %d\n",
		nBelow, distLabels[aboveI], counts[aboveI])
	var empty []string
	for i := 0; i < aboveI; i++ {
		if counts[i] == 0 {
			empty = append(empty, distLabels[i])
		}
	}
	if len(empty) > 0 {
		fmt.Fprintf(w, "  empty bucket(s) below the line: %s -- the clean separation is there, not at %d%%\n",
			strings.Join(empty, ", "), int(tol*100))
	}
	if counts[aboveI] > 0 && nBelow > 0 {
		fmt.Fprintf(w, "  both sides of the line are populated: the tolerance is cutting a continuum,\n")
		fmt.Fprintf(w, "  so a different number would change verdicts. A low failure rate is not\n")
		fmt.Fprintf(w, "  evidence that %d%% is the right one.\n", int(tol*100))
	}

	var fails []rat
	for _, r := range rats {
		if r.R < tol {
			fails = append(fails, r)
		}
	}
	sort.Slice(fails, func(i, j int) bool { return fails[i].R < fails[j].R })
	if len(fails) == 0 {
		return 0
	}
	// Acknowledged rows are separated because they are NOT the gate misfiring
	// -- they are a known cause the gate is told to report rather than fail
	// on, and mixing them into a failure list overstates the failure rate by
	// however many of them there are.
	var known, real []rat
	for _, r := range fails {
		if _, ok := acks[r.Target]; ok {
			known = append(known, r)
		} else {
			real = append(real, r)
		}
	}
	fmt.Fprintf(w, "\n== below the line: %d unacknowledged, %d known\n", len(real), len(known))
	for _, grp := range []struct {
		Label string
		Rows  []rat
	}{{"", real}, {"known (reported, not failed)", known}} {
		if len(grp.Rows) == 0 {
			continue
		}
		if grp.Label != "" {
			fmt.Fprintf(w, "\n  %s:\n", grp.Label)
		}
		for _, r := range grp.Rows {
			fmt.Fprintf(w, "    %6.1f%%  %-18s %-24s %12s of %13s\n",
				r.R*100, r.WS, r.Target, commaInt(r.V), commaInt(r.F))
		}
	}
	tgts := map[string]int{}
	for _, r := range real {
		tgts[r.Target]++
	}
	if len(tgts) > 0 {
		var parts []string
		for _, t := range byCountDesc(tgts) {
			parts = append(parts, fmt.Sprintf("%s x%d", t, tgts[t]))
		}
		fmt.Fprintf(w, "\n  %d failure(s) across %d distinct target(s): %s\n",
			len(real), len(tgts), strings.Join(parts, ", "))
		fmt.Fprintln(w, "  Repeats concentrated on few targets are structure. Scattered")
		fmt.Fprintln(w, "  singletons would be noise.")
	}
	return 0
}

func sinceNote(since string) string {
	if since == "" {
		return ""
	}
	return " at or after " + since
}

func byCountDesc(m map[string]int) []string {
	var ks []string
	for k := range m {
		ks = append(ks, k)
	}
	// Ties break ALPHABETICALLY. The tool that came before broke them by the
	// order keys happened to be inserted, which is the order they appeared in
	// the JSON -- reproducible, but only for one particular series file. Two
	// targets with the same count are not ranked by which was written first.
	sort.Slice(ks, func(i, j int) bool {
		if m[ks[i]] != m[ks[j]] {
			return m[ks[i]] > m[ks[j]]
		}
		return ks[i] < ks[j]
	})
	return ks
}

func median(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	s := append([]float64(nil), xs...)
	sort.Float64s(s)
	m := len(s) / 2
	if len(s)%2 == 1 {
		return s[m]
	}
	return (s[m-1] + s[m]) / 2
}

// mad is the median absolute deviation, scaled to be comparable to a standard
// deviation.
//
// Robust on purpose. This data has a death cluster near zero -- a target that
// executed 8 inputs against a record of 441,993 -- and a plain standard
// deviation computed over that would be inflated by the very events the
// detector is supposed to fire on, raising its own threshold out of reach.
func mad(xs []float64, med float64) float64 {
	d := make([]float64, len(xs))
	for i, x := range xs {
		d[i] = math.Abs(x - med)
	}
	return 1.4826 * median(d)
}

func commaInt(n int) string {
	s := fmt.Sprintf("%d", n)
	neg := strings.HasPrefix(s, "-")
	s = strings.TrimPrefix(s, "-")
	var out []byte
	for i, c := range []byte(s) {
		if i > 0 && (len(s)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, c)
	}
	if neg {
		return "-" + string(out)
	}
	return string(out)
}

// commaFloat1 groups the integer part of a one-decimal number.
//
// Rounded FIRST, then split. Truncating the integer part and rounding the
// fraction separately turns 3052.96 into "3,052.0" instead of "3,053.0" --
// the two halves disagreeing about which number they are describing.
func commaFloat1(f float64) string {
	s := strconv.FormatFloat(f, 'f', 1, 64)
	dot := strings.LastIndex(s, ".")
	n, _ := strconv.Atoi(s[:dot])
	return commaInt(n) + s[dot:]
}

// pyFloat renders a float the way the tool that came before rendered it, so a
// threshold printed in a log reads the same across the change: an integral
// value keeps its ".0" rather than collapsing to a bare integer.
func pyFloat(f float64) string {
	s := strconv.FormatFloat(f, 'f', -1, 64)
	if !strings.ContainsAny(s, ".eE") {
		s += ".0"
	}
	return s
}

// LoadAcks reads known-starved.tsv: target -> the reason row.
func LoadAcks(path string) (map[string]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return map[string]string{}, err
	}
	acks := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, "\t")
		acks[parts[0]] = line
	}
	return acks, nil
}

// Variance measures how much a healthy target moves between rounds.
//
// The tolerance has to sit BELOW the worst honest round and ABOVE the noise,
// and those two numbers are empirical. Guessing produces one of the two ways a
// gate dies: too tight and it cries wolf until somebody disables it, too loose
// and it never catches anything. So measure first.
//
// ALL rounds, not the first two. The floor is the maximum a pair has ever
// achieved, so the distribution that matters is worst-round / best-ever -- not
// the spread between two adjacent rounds. Those differ, and the first draft of
// this measured the second while the gate used the first: it reported a worst
// honest swing of 16.1% while the checker was rejecting a real round at 8.5%,
// because that round's floor came from a third round the comparison never
// looked at.
//
// READ FROM THE SERIES, NOT FROM THE SWEEP LOGS. This is a deliberate change
// from the tool that came before, and it changes the answer: on pg16-15-und
// the log-based version found 2 targets across 12 rounds and reported a worst
// honest swing of 57.7%, while the series holds 22 targets across 16 and the
// worst is 0.1%.
//
// The series wins for two reasons. It is append-only and durable, whereas
// sweep logs are compressed and eventually removed -- so a log-based variance
// silently narrows as the disk is tidied, and narrows toward "the spread is
// small", which is the direction that gets believed. And a target absent from
// any single log drops out of the intersection entirely, so the log-based
// sample was small enough that no tolerance could honestly be set from it.
func Variance(w io.Writer, rows []SeriesRow, only string) int {
	byWS := map[string][]SeriesRow{}
	for _, r := range rows {
		if only == "" || r.WS == only {
			byWS[r.WS] = append(byWS[r.WS], r)
		}
	}
	var wss []string
	for ws, rs := range byWS {
		if len(rs) >= 2 {
			wss = append(wss, ws)
		}
	}
	sort.Strings(wss)
	if len(wss) == 0 {
		fmt.Fprintln(w, "need a workspace with at least two recorded rounds")
		return 2
	}

	type swing struct {
		R          float64
		WS, Target string
		Lo, Hi     int
	}
	var ratios []swing
	for _, ws := range wss {
		rs := byWS[ws]
		// Only targets present in EVERY round: a target that appeared once
		// has no spread, and counting it as 100% would dilute the tail this
		// exists to find.
		common := map[string]bool{}
		for t := range rs[0].Execs {
			common[t] = true
		}
		for _, r := range rs[1:] {
			for t := range common {
				if _, ok := r.Execs[t]; !ok {
					delete(common, t)
				}
			}
		}
		for t := range common {
			lo, hi := math.MaxInt, 0
			for _, r := range rs {
				v := r.Execs[t]
				if v < lo {
					lo = v
				}
				if v > hi {
					hi = v
				}
			}
			if hi > 0 {
				ratios = append(ratios, swing{float64(lo) / float64(hi), ws, t, lo, hi})
			}
		}
		fmt.Fprintf(w, "  %s: %d target(s) across %d recorded round(s)\n", ws, len(common), len(rs))
	}
	if len(ratios) == 0 {
		fmt.Fprintln(w, "no target appeared in two rounds")
		return 2
	}
	sort.Slice(ratios, func(i, j int) bool { return ratios[i].R < ratios[j].R })
	n := len(ratios)
	pct := func(p float64) float64 {
		i := int(float64(n) * p)
		if i > n-1 {
			i = n - 1
		}
		return ratios[i].R
	}
	// Name the source. Two runs of this over different records give different
	// numbers, and a percentile with no provenance invites the reader to
	// compare it with one taken from somewhere else.
	fmt.Fprintf(w, "\n  worse-round / better-round, %d pairs, from the recorded series\n", n)
	for _, p := range []float64{0.01, 0.05, 0.10, 0.25, 0.50} {
		fmt.Fprintf(w, "    p%-3d %6.1f%%\n", int(p*100), pct(p)*100)
	}
	fmt.Fprintln(w, "\n  the ten widest swings:")
	for i, x := range ratios {
		if i >= 10 {
			break
		}
		fmt.Fprintf(w, "    %5.1f%%  %-18s %-24s %12s vs %12s\n",
			x.R*100, x.WS, x.Target, commaInt(x.Lo), commaInt(x.Hi))
	}
	// NOT "put the tolerance below p1". This distribution is bimodal: healthy
	// rounds cluster high, and the low tail is mostly REAL breakage -- targets
	// that executed 8 inputs, not targets having a slow day. Setting the
	// threshold below the tail would tolerate exactly what the gate exists to
	// catch.
	fmt.Fprintln(w, "\n  This distribution is bimodal. The low tail is mostly real breakage,")
	fmt.Fprintln(w, "  not noise -- check the swings above before treating any percentile")
	fmt.Fprintln(w, "  as a noise floor. Put the tolerance in the GAP, not below p1.")
	return 0
}

// Reseed lowers a target's floors on purpose, because the target legitimately
// changed.
//
// The ratchet refuses to lower a floor by itself, and should. But a floor can
// become genuinely unreachable -- and the sharpest example is a target that was
// FAST BECAUSE IT WAS BROKEN.
//
// protocol_fuzzer held a floor of 21,171,256 executions earned while it
// consumed one byte of each input and died; after the fix it does 1.5-6.9M
// executions at cov 4,077 instead of 380. Throughput fell because each input
// finally does real work. Ratcheting against the broken number would mean
// demanding the bug back.
//
// So: recompute from logs newer than since, REQUIRE a reason, and record that
// reason in the baseline next to the changed floors, so the lowering is
// self-documenting rather than an unexplained number somebody has to trust.
type ReseedChange struct {
	Workspace string `json:"workspace"`
	From      int    `json:"from"`
	To        int    `json:"to"`
}

// ReseedRecord is what the baseline keeps about one reseed.
type ReseedRecord struct {
	Target  string         `json:"target"`
	Since   string         `json:"since"`
	Reason  string         `json:"reason"`
	Changed []ReseedChange `json:"changed"`
}

// Reseed recomputes one target's floors from qualifying rounds.
//
// best is supplied by the caller so this stays testable without a workspace
// tree: it returns the highest execution count that target reached in any
// round of ws at or after since, and 0 when no round qualifies.
func (b *Baseline) Reseed(target, since, reason string, wsDirs map[string]string,
	best func(wsDir, target, since string) int, w io.Writer) ([]ReseedChange, error) {

	if reason == "" {
		// Not optional. A lowered floor with no reason is an unexplained
		// number somebody later has to take on trust, which is the thing the
		// committed baseline exists to prevent.
		return nil, fmt.Errorf("reseed needs a reason")
	}
	var changed []ReseedChange
	var wss []string
	for ws := range b.Floors {
		wss = append(wss, ws)
	}
	sort.Strings(wss)

	for _, ws := range wss {
		old, ok := b.Floors[ws][target]
		if !ok {
			continue
		}
		dir, ok := wsDirs[ws]
		if !ok {
			continue
		}
		n := best(dir, target, since)
		if n <= 0 {
			// Said out loud. A workspace silently left alone reads as one that
			// was reseeded and happened not to move.
			fmt.Fprintf(w, "  %s: no qualifying round -- left at %s\n", ws, commaInt(old))
			continue
		}
		if n == old {
			continue
		}
		b.Floors[ws][target] = n
		changed = append(changed, ReseedChange{ws, old, n})
		arrow := "raised"
		if n < old {
			arrow = "LOWERED"
		}
		fmt.Fprintf(w, "  %s: %s %s -> %s  (%s)\n", ws, target, commaInt(old), commaInt(n), arrow)
	}
	if len(changed) == 0 {
		fmt.Fprintln(w, "  nothing changed")
		return nil, nil
	}

	var rs []ReseedRecord
	if len(b.Reseeds) > 0 {
		_ = json.Unmarshal(b.Reseeds, &rs)
	}
	rs = append(rs, ReseedRecord{target, since, reason, changed})
	raw, err := json.Marshal(rs)
	if err != nil {
		return nil, err
	}
	b.Reseeds = raw
	fmt.Fprintf(w, "\n  %d floor(s) reseeded; reason recorded in the baseline\n", len(changed))
	return changed, nil
}

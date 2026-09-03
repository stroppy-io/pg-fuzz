package tui

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// The growth panel: is the corpus still climbing, and is coverage following?
//
// A pass/fail dashboard cannot answer that. A corpus of 43,361 that grew by 0
// last round and one of 227 that grew by 2,324 are telling opposite stories,
// and only the delta distinguishes them.

// spark is the eight-step block ramp.
const spark = "▁▂▃▄▅▆▇█"

// Sparkline draws a growth curve in one line of text.
//
// Scaled between the min and max OF THE WINDOW SHOWN, not from zero. A corpus
// going 254,405 -> 254,900 is flat in absolute terms, and the question worth
// answering is whether it is still climbing at all -- which a zero-based scale
// would hide completely. The numbers beside it carry the magnitude.
func Sparkline(values []int, width int) string {
	vals := values
	if len(vals) > width {
		vals = vals[len(vals)-width:]
	}
	if len(vals) < 2 {
		return strings.Repeat("·", len(vals))
	}
	lo, hi := vals[0], vals[0]
	for _, v := range vals {
		if v < lo {
			lo = v
		}
		if v > hi {
			hi = v
		}
	}
	if hi == lo {
		// Flat, and saying so is the point.
		return strings.Repeat("─", len(vals))
	}
	runes := []rune(spark)
	var b strings.Builder
	for _, v := range vals {
		i := 7 * (v - lo) / (hi - lo)
		if i > 7 {
			i = 7
		}
		b.WriteRune(runes[i])
	}
	return b.String()
}

// CorpusPoint is one observation of a workspace's corpus.
type CorpusPoint struct {
	Round *int
	Total int
}

// CorpusHistory reads a workspace's corpus totals, oldest first.
func CorpusHistory(seriesPath, ws string) []CorpusPoint {
	f, err := os.Open(seriesPath)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []CorpusPoint
	dec := json.NewDecoder(f)
	for {
		var r struct {
			WS     string         `json:"ws"`
			Round  *int           `json:"round"`
			Corpus map[string]int `json:"corpus"`
		}
		if err := dec.Decode(&r); err != nil {
			break
		}
		if r.WS != ws || len(r.Corpus) == 0 {
			continue
		}
		t := 0
		for _, v := range r.Corpus {
			t += v
		}
		out = append(out, CorpusPoint{r.Round, t})
	}
	return out
}

// RepresentativeTarget is the one target whose coverage means something on its
// own.
//
// NOT a sum across targets. Summing covered/count over several reports of the
// same ~550k-line codebase counts the denominator once per report and produced
// a meaningless 7.81% that looked like a real figure. Each report is coverage
// of the whole tree BY ONE TARGET, so the honest single number is one
// target's, named rather than blended.
//
// spi_query_fuzzer reaches the executor, the catalog and every extension hook
// at ~27%, while raw_parser, binary_recv and jsonb sit at 1.2-1.8% because
// they parse or decode and stop.
const RepresentativeTarget = "spi_query_fuzzer"

// CoverageHistory reads one target's covered-line counts, oldest first.
func CoverageHistory(seriesPath, target string) []int {
	f, err := os.Open(seriesPath)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []int
	dec := json.NewDecoder(f)
	for {
		var r struct {
			Target string                       `json:"target"`
			Lines  struct{ Count, Covered int } `json:"lines"`
		}
		if err := dec.Decode(&r); err != nil {
			break
		}
		if r.Target == target && r.Lines.Count > 0 {
			out = append(out, r.Lines.Covered)
		}
	}
	return out
}

// GrowthPanel renders one line per workspace, plus the coverage curve.
func GrowthPanel(ratchetSeries, coverageSeries string, workspaces []string, width int) []string {
	var out []string
	for _, name := range workspaces {
		h := CorpusHistory(ratchetSeries, name)
		if len(h) == 0 {
			continue
		}
		cur, first := h[len(h)-1].Total, h[0].Total
		var delta float64
		if first != 0 {
			delta = 100 * float64(cur-first) / float64(first)
		}
		vals := make([]int, len(h))
		for i, p := range h {
			vals[i] = p.Total
		}
		// Round numbers are ABSENT from soak-written rows, which printed a
		// literal "rNone" and "since r1" -- a label that looked like a round
		// and was not one. Fall back to the observation count, the way the
		// coverage line already does, so the units are honest either way.
		label, span := fmt.Sprintf("n=%d", len(h)), "over the series"
		if h[len(h)-1].Round != nil && h[0].Round != nil {
			label = fmt.Sprintf("r%d", *h[len(h)-1].Round)
			span = fmt.Sprintf("since r%d", *h[0].Round)
		}
		out = append(out, fmt.Sprintf("  corpus %-20s %s  %s  %9s  %+.1f%% %s",
			name, Sparkline(vals, width), label, comma(cur), delta, span))
	}
	if cov := CoverageHistory(coverageSeries, RepresentativeTarget); len(cov) > 0 {
		cur, first := cov[len(cov)-1], cov[0]
		var d float64
		if first != 0 {
			d = 100 * float64(cur-first) / float64(first)
		}
		out = append(out, fmt.Sprintf("  cov    %-20s %s  n=%d  %9s  %+.1f%%",
			"spi_query (lines)", Sparkline(cov, width), len(cov), comma(cur), d))
	}
	return out
}

// CoveragePct is the newest recorded line coverage for a workspace.
//
// FROM THE -cov WORKSPACE, because coverage is measured in its own
// instrumented build: pg17-add's coverage lives under pg17-cov. The old
// dashboard did this remap and the port dropped both it and the column's
// only writer, so Row.CovPct was declared, read by the renderer, and assigned
// by nobody -- the column read "-" forever.
//
// Zero means "not recorded", which the caller renders as "-" rather than as
// a measured zero. Those are different states and the grid has to keep them
// apart.
func CoveragePct(seriesPath, ws string) float64 {
	f, err := os.Open(seriesPath)
	if err != nil {
		return 0
	}
	defer f.Close()

	want := CovWorkspace(ws)
	var pct float64
	dec := json.NewDecoder(f)
	for {
		var r struct {
			WS    string `json:"ws"`
			Lines struct {
				Count, Covered int
			} `json:"lines"`
		}
		if err := dec.Decode(&r); err != nil {
			break
		}
		// Newest wins, and a row with no denominator is not a measurement.
		if r.WS == want && r.Lines.Count > 0 {
			pct = float64(r.Lines.Covered) * 100 / float64(r.Lines.Count)
		}
	}
	return pct
}

// CovWorkspace maps a fuzzing workspace to the one its coverage is measured
// in: pg17-add and pg17-und are both covered by pg17-cov.
func CovWorkspace(ws string) string {
	for _, suffix := range []string{"-add", "-und"} {
		if strings.HasSuffix(ws, suffix) {
			return strings.TrimSuffix(ws, suffix) + "-cov"
		}
	}
	return ws
}

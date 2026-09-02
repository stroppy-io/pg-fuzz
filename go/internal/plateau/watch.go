package plateau

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Options tunes the watch. The defaults are what the campaign ran with.
type Options struct {
	Window       time.Duration
	Interval     time.Duration
	CorpusMargin float64
	CovMargin    float64
	Consecutive  int
	LogPatterns  []string
	Samples      string // where to append each sample
	Ledger       string // the cap's removal ledger
	Once         bool
	MaxHours     float64
	Out          io.Writer
}

// Defaults fills in the campaign's values.
func Defaults() Options {
	return Options{
		Window: 45 * time.Minute, Interval: time.Minute,
		CorpusMargin: 1.0, CovMargin: 0.5, Consecutive: 2,
		LogPatterns: []string{"sweep-round", "soak-"},
	}
}

// Watch samples until a plateau, a time limit, or cancellation.
//
// Returns 0 on plateau, 2 when the time limit passed without one. The
// distinction matters: "we stopped watching" and "it converged" are different
// facts, and a single exit code for both would let a timeout be reported as a
// finished campaign.
func Watch(ctx context.Context, wsRoot string, workspaces []string, o Options) int {
	if o.Out == nil {
		o.Out = os.Stdout
	}
	tails := map[string]*LogTail{}
	cov := map[string]map[string]int{}
	curT := map[string]string{}
	corpusSeries := map[string][]Sample{}
	covByTarget := map[string]map[string][]Sample{}
	for _, ws := range workspaces {
		tails[ws] = NewLogTail()
		cov[ws] = map[string]int{}
		covByTarget[ws] = map[string][]Sample{}
	}
	flatRuns := 0
	started := time.Now()

	for {
		now := time.Now()
		for _, ws := range workspaces {
			dir := filepath.Join(wsRoot, ws)
			for _, lg := range LiveLogs(dir, o.LogPatterns) {
				text := tails[ws].Read(lg.Path)
				if lg.Target != "" {
					// The filename names the target; banners are irrelevant.
					ScanCov(text, lg.Target, cov[ws])
				} else {
					curT[ws] = ScanCov(text, curT[ws], cov[ws])
				}
			}
			corpusSeries[ws] = append(corpusSeries[ws],
				Sample{now, CorpusCount(dir, o.Ledger, ws)})
			// PER-TARGET, never the sum.
			//
			// Summing across targets measures how many targets have been
			// OBSERVED, not how much has been covered: a sweep visits targets
			// in turn, so the total climbs as each one is first seen and jumps
			// again every new log.
			for t, v := range cov[ws] {
				covByTarget[ws][t] = append(covByTarget[ws][t], Sample{now, v})
			}
		}

		cg := map[string]*float64{}
		vg := map[string]*float64{}
		for _, ws := range workspaces {
			cg[ws] = Growth(corpusSeries[ws], o.Window, now)
			// Reduced with MAX, because plateau means no target is still
			// gaining: the slowest to settle decides, and a dead target
			// contributes zero instead of dominating.
			var best *float64
			for _, series := range covByTarget[ws] {
				if g := Growth(series, o.Window, now); g != nil {
					if best == nil || *g > *best {
						v := *g
						best = &v
					}
				}
			}
			vg[ws] = best
		}

		// Corpus is the PRIMARY signal, and it is not a proxy for coverage --
		// it IS coverage, counted. libFuzzer writes a corpus file only when an
		// input produces new coverage, so the file count is a monotone
		// function of discovered features and is observable continuously.
		//
		// Coverage from `cov:` is secondary and often absent: with -jobs=N
		// libFuzzer writes each worker's running output inside the container
		// and only surfaces INITED/DONE at the end, so in a soak there is at
		// most one coverage sample per slice. Requiring it would mean never
		// reaching a verdict.
		haveCov := false
		for _, v := range vg {
			if v != nil {
				haveCov = true
			}
		}
		ready := true
		for _, ws := range workspaces {
			if cg[ws] == nil {
				ready = false
			}
		}
		corpusFlat, covFlat := true, true
		for _, ws := range workspaces {
			if !Flat(cg[ws], o.CorpusMargin) {
				corpusFlat = false
			}
			if vg[ws] != nil && !Flat(vg[ws], o.CovMargin) {
				covFlat = false
			}
		}
		if !haveCov {
			covFlat = true
		}
		if ready && corpusFlat && covFlat {
			flatRuns++
		} else if ready {
			flatRuns = 0
		}

		var parts []string
		for _, ws := range workspaces {
			short := ws
			if i := strings.LastIndex(ws, "-"); i >= 0 {
				short = ws[i+1:]
			}
			edges := 0
			for _, s := range covByTarget[ws] {
				edges += s[len(s)-1].V
			}
			parts = append(parts, fmt.Sprintf("%s: corpus %d (%s) cov %d across %d tgt (%s max)",
				short, corpusSeries[ws][len(corpusSeries[ws])-1].V, pctOrDash(cg[ws]),
				edges, len(covByTarget[ws]), pctOrDash(vg[ws])))
		}
		line := now.Format("15:04:05") + " " + strings.Join(parts, " | ")
		if ready {
			if corpusFlat && covFlat {
				line += fmt.Sprintf(" | flat %d/%d", flatRuns, o.Consecutive)
			}
		} else {
			line += fmt.Sprintf(" | filling window (%gm)", o.Window.Minutes())
		}
		if ready && !haveCov {
			line += " | corpus-only (no cov samples yet)"
		}
		fmt.Fprintln(o.Out, line)

		if o.Samples != "" {
			appendSample(o.Samples, now, workspaces, corpusSeries, covByTarget, cg, vg, flatRuns)
		}

		if o.Once {
			return 0
		}
		if flatRuns >= o.Consecutive {
			what := "corpus"
			if haveCov {
				what = "corpus and coverage"
			}
			fmt.Fprintf(o.Out, "PLATEAU %s inside margins for %d consecutive %gm windows\n",
				what, o.Consecutive, o.Window.Minutes())
			return 0
		}
		if o.MaxHours > 0 && time.Since(started).Hours() > o.MaxHours {
			fmt.Fprintf(o.Out, "STOPPED no plateau within %gh\n", o.MaxHours)
			return 2
		}
		select {
		case <-ctx.Done():
			fmt.Fprintln(o.Out, "STOPPED interrupted; no verdict")
			return 2
		case <-time.After(o.Interval):
		}
	}
}

func pctOrDash(v *float64) string {
	if v == nil {
		return "  --  "
	}
	return fmt.Sprintf("%+.2f%%", *v)
}

func appendSample(path string, now time.Time, workspaces []string,
	corpusSeries map[string][]Sample, covByTarget map[string]map[string][]Sample,
	cg, vg map[string]*float64, flatRuns int) {

	corpus := map[string]int{}
	covOut := map[string]map[string]int{}
	for _, ws := range workspaces {
		corpus[ws] = corpusSeries[ws][len(corpusSeries[ws])-1].V
		m := map[string]int{}
		var ts []string
		for t := range covByTarget[ws] {
			ts = append(ts, t)
		}
		sort.Strings(ts)
		for _, t := range ts {
			s := covByTarget[ws][t]
			m[t] = s[len(s)-1].V
		}
		covOut[ws] = m
	}
	raw, err := json.Marshal(map[string]any{
		"when": float64(now.UnixNano()) / 1e9, "corpus": corpus, "cov": covOut,
		"corpus_growth": cg, "cov_growth": vg, "flat": flatRuns,
	})
	if err != nil {
		return
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	f.Write(append(raw, '\n'))
}

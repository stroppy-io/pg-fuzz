package report

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
)

// The run funnel: how inputs become findings.
//
// Six stages, and the last two are DELIBERATELY BLANK. Signatures need triage
// and findings need a human, so a number there would be an invention -- and a
// funnel that fills in its own bottom two rows is exactly how "2,134 artifacts"
// gets read as "2,134 defects".

// FunnelRecord is one target's line in a campaign record file.
//
// TWO SCHEMAS, one reader. The record files written before the port name the
// corpus corpus_before/corpus_after; the series the campaign writes now names
// the end state "corpus" and carries corpus_before beside it. Both are on
// disk and both are worth reading -- a reader that understands only the
// current one cannot open last month's campaign, and one that understands only
// the old one cannot open today's.
type FunnelRecord struct {
	Target string `json:"target"`
	Round  *int   `json:"round"`
	Alive  bool   `json:"alive"`
	// A POINTER, because absent and zero are different claims. A row written
	// before this field existed has no starting corpus, and reading that as
	// zero says a fifteen-second slice created 407,614 inputs from nothing.
	CorpusBefore    *int     `json:"corpus_before"`
	CorpusAfter     int      `json:"corpus_after"`
	Corpus          int      `json:"corpus"`
	Cov             int      `json:"cov"`
	Ft              int      `json:"ft"`
	ArtifactsBefore int      `json:"artifacts_before"`
	ArtifactsAfter  int      `json:"artifacts_after"`
	CovGained       int      `json:"cov_gained_in_run"`
	FtGained        int      `json:"ft_gained_in_run"`
	SaturatedPct    *float64 `json:"saturated_pct"`
}

// Stage is one rung of the funnel.
type Stage struct {
	Name  string
	Count int
	Known bool // false renders as a dash: the number needs a human
	What  string
}

// ReadFunnelRecords loads a campaign record file.
func ReadFunnelRecords(path string) ([]FunnelRecord, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []FunnelRecord
	dec := json.NewDecoder(f)
	for {
		var r FunnelRecord
		if err := dec.Decode(&r); err != nil {
			break
		}
		// The series form names the end state "corpus"; normalise to the one
		// the funnel reads, so neither shape needs a second code path.
		if r.CorpusAfter == 0 && r.Corpus != 0 {
			r.CorpusAfter = r.Corpus
		}
		out = append(out, r)
	}
	return out, nil
}

// LatestPerTarget keeps each target's newest record.
//
// A campaign file appends a row per slice, so the totals must come from the
// LAST row per target -- summing every row would count a corpus once per
// slice it survived.
func LatestPerTarget(recs []FunnelRecord) map[string]FunnelRecord {
	last := map[string]FunnelRecord{}
	for _, r := range recs {
		last[r.Target] = r
	}
	return last
}

// Funnel rolls the latest records into the six stages.
func Funnel(last map[string]FunnelRecord) []Stage {
	var corpus, ft, cov, arts int
	for _, r := range last {
		corpus += r.CorpusAfter
		ft += r.Ft
		cov += r.Cov
		arts += r.ArtifactsAfter - r.ArtifactsBefore
	}
	return []Stage{
		{"exemplars", corpus, true, "distinct inputs kept -- the corpus"},
		{"features", ft, true, "(edge, hit-bucket) pairs -- behaviours"},
		{"coverage", cov, true, "edges -- code reached"},
		{"artifacts", arts, true, "crash/OOM/timeout files this run"},
		{"signatures", 0, false, "deduped by failure site (needs triage)"},
		{"findings", 0, false, "confirmed defects in FINDINGS/ (needs a human)"},
	}
}

// ShowFunnel prints one run's funnel.
func ShowFunnel(out io.Writer, last map[string]FunnelRecord, label string, rounds []int) {
	var dead []string
	for t, r := range last {
		if !r.Alive {
			dead = append(dead, t)
		}
	}
	sort.Strings(dead)

	fmt.Fprintf(out, "FUNNEL  %s\n", label)
	rs := "?"
	if len(rounds) > 0 {
		rs = fmt.Sprint(rounds)
	}
	tail := "   none dead"
	if len(dead) > 0 {
		tail = "   DEAD: " + join(dead, ", ")
	}
	fmt.Fprintf(out, "  round(s) %s   %d target(s) recorded%s\n\n", rs, len(last), tail)

	prev := 0
	for _, s := range Funnel(last) {
		if !s.Known {
			fmt.Fprintf(out, "  %-11s %13s                    %s\n", s.Name, "—", s.What)
			continue
		}
		conv := "                     "
		if prev != 0 {
			conv = fmt.Sprintf("%9.4f%% of prev", float64(s.Count)/float64(prev)*100)
		}
		fmt.Fprintf(out, "  %-11s %13s  %s  %s\n", s.Name, comma(s.Count), conv, s.What)
		prev = s.Count
	}

	var cg, fg int
	for _, r := range last {
		cg += r.CovGained
		fg += r.FtGained
	}
	fmt.Fprintf(out, "\n  WITHIN-RUN GAIN  (did it climb *during* the run?)\n")
	if cg != 0 || fg != 0 {
		fmt.Fprintf(out, "    coverage +%s edges     features +%s\n", comma(cg), comma(fg))
		type tg struct {
			G int
			T string
		}
		var all []tg
		for t, r := range last {
			all = append(all, tg{r.CovGained, t})
		}
		sort.Slice(all, func(i, j int) bool {
			if all[i].G != all[j].G {
				return all[i].G > all[j].G
			}
			return all[i].T < all[j].T
		})
		var best []string
		for i, x := range all {
			if i >= 3 || x.G == 0 {
				break
			}
			best = append(best, fmt.Sprintf("%s +%s", x.T, comma(x.G)))
		}
		if len(best) > 0 {
			fmt.Fprintf(out, "    biggest: %s\n", join(best, ", "))
		}
	} else {
		// Said out loud. A blank line here would read as "it did not climb".
		fmt.Fprintln(out, "    not recorded -- this run predates the measurement")
	}

	grew, delta, known := 0, 0, 0
	for _, r := range last {
		if r.CorpusBefore == nil {
			continue
		}
		known++
		if d := r.CorpusAfter - *r.CorpusBefore; d > 0 {
			grew++
			delta += d
		}
	}
	if known == 0 {
		// Said, not left blank. "No growth" and "growth was never recorded"
		// look identical in a table and mean opposite things.
		fmt.Fprintf(out, "    corpus growth not recorded for this run\n")
	} else {
		fmt.Fprintf(out, "    corpus grew for %d/%d targets, +%s inputs%s\n",
			grew, known, comma(delta), partial(known, len(last)))
	}

	var climbing []string
	for t, r := range last {
		if r.SaturatedPct != nil && *r.SaturatedPct < 50 {
			climbing = append(climbing, t)
		}
	}
	sort.Strings(climbing)
	line := fmt.Sprintf("    still climbing at cutoff: %d", len(climbing))
	if len(climbing) > 0 {
		line += " (" + join(climbing, ", ") + ")"
	}
	fmt.Fprintln(out, line)
}

// CompareFunnels prints two runs side by side.
func CompareFunnels(out io.Writer, a, b map[string]FunnelRecord, la, lb string) {
	fmt.Fprintf(out, "COMPARE  %s  ->  %s\n\n", la, lb)
	fmt.Fprintf(out, "  %-11s %13s %13s %13s\n", "stage", "before", "after", "delta")
	sa, sb := Funnel(a), Funnel(b)
	for i := range sa {
		if !sa[i].Known || !sb[i].Known {
			fmt.Fprintf(out, "  %-11s %13s %13s %13s\n", sa[i].Name, "—", "—", "—")
			continue
		}
		d := sb[i].Count - sa[i].Count
		sign := "+"
		if d < 0 {
			sign = "-"
			d = -d
		}
		fmt.Fprintf(out, "  %-11s %13s %13s %13s\n", sa[i].Name,
			comma(sa[i].Count), comma(sb[i].Count), sign+comma(d))
	}
}

// Rounds lists the round numbers a record file covers.
func Rounds(recs []FunnelRecord) []int {
	seen := map[int]bool{}
	var out []int
	for _, r := range recs {
		if r.Round != nil && *r.Round != 0 && !seen[*r.Round] {
			seen[*r.Round] = true
			out = append(out, *r.Round)
		}
	}
	sort.Ints(out)
	return out
}

func join(xs []string, sep string) string {
	out := ""
	for i, x := range xs {
		if i > 0 {
			out += sep
		}
		out += x
	}
	return out
}

// partial names how much of the population a figure covers, when it does not
// cover all of it.
func partial(known, total int) string {
	if known == total {
		return ""
	}
	return fmt.Sprintf(" (%d of %d rows carry a starting corpus)", known, total)
}

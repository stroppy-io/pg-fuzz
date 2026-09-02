package report

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

// Rendering a campaign record file into a report you can act on.
//
// Reads ONLY the record. Nothing here is remembered, inferred or carried over
// between runs, so two reports of the same file are the same report.

// CampaignRecord is one target's line.
type CampaignRecord struct {
	Target          string   `json:"target"`
	Round           int      `json:"round"`
	Build           string   `json:"build"`
	PGSHA           string   `json:"pg_sha"`
	Workspace       string   `json:"workspace"`
	Alive           bool     `json:"alive"`
	Dict            bool     `json:"dict"`
	Execs           int      `json:"execs"`
	LastExecSeen    int      `json:"last_exec_seen"`
	Cov             *int     `json:"cov"`
	Ft              *int     `json:"ft"`
	CorpusBefore    int      `json:"corpus_before"`
	CorpusAfter     int      `json:"corpus_after"`
	Corpus          int      `json:"corpus"` // the series form's end state
	LastNewEdgeAt   *int     `json:"last_new_edge_at"`
	SaturatedPct    *float64 `json:"saturated_pct"`
	ArtifactsBefore int      `json:"artifacts_before"`
	ArtifactsAfter  int      `json:"artifacts_after"`
}

// ExecCount prefers the recorded total, falling back to the last figure seen.
//
// The fallback exists for a target the run could not finish cleanly: its
// stats line never printed, and reporting zero would say it executed nothing.
func (r CampaignRecord) ExecCount() int {
	if r.Execs != 0 {
		return r.Execs
	}
	return r.LastExecSeen
}

// ReadCampaignRecords loads a record file.
func ReadCampaignRecords(path string) ([]CampaignRecord, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []CampaignRecord
	dec := json.NewDecoder(f)
	for {
		var r CampaignRecord
		if err := dec.Decode(&r); err != nil {
			break
		}
		if r.CorpusAfter == 0 && r.Corpus != 0 {
			r.CorpusAfter = r.Corpus
		}
		out = append(out, r)
	}
	return out, nil
}

// latestCampaign keeps each target's newest record. File order is
// chronological.
func latestCampaign(recs []CampaignRecord) map[string]CampaignRecord {
	out := map[string]CampaignRecord{}
	for _, r := range recs {
		out[r.Target] = r
	}
	return out
}

// CampaignReport renders one record file.
func CampaignReport(out io.Writer, path string, recs []CampaignRecord) int {
	if len(recs) == 0 {
		fmt.Fprintln(out, "empty record")
		return 1
	}
	last := latestCampaign(recs)
	b := recs[0]

	rounds := map[int]bool{}
	total := 0
	for _, r := range recs {
		rounds[r.Round] = true
		total += r.ExecCount()
	}

	fmt.Fprintf(out, "# Campaign report\n\n")
	fmt.Fprintf(out, "**Build:** `%s` @ `%s`  \n", b.Build, orQ(b.PGSHA))
	fmt.Fprintf(out, "**Workspace:** `%s`  \n", b.Workspace)
	fmt.Fprintf(out, "**Records:** %d across %d round(s), %d targets  \n",
		len(recs), len(rounds), len(last))
	fmt.Fprintf(out, "**Source:** `%s`\n\n", path)

	var dead, nodict, badly, growing []string
	nsat := 0
	for t, r := range last {
		if !r.Alive {
			dead = append(dead, t)
		}
		if !r.Dict {
			nodict = append(nodict, t)
		}
		if r.SaturatedPct != nil {
			nsat++
			if *r.SaturatedPct >= 99 {
				badly = append(badly, t)
			}
			if *r.SaturatedPct < 50 {
				growing = append(growing, t)
			}
		}
	}
	sort.Strings(dead)
	sort.Strings(nodict)
	sort.Strings(badly)
	sort.Strings(growing)

	// CORRECTNESS FIRST. A saturation figure for a target that executed
	// nothing is a number about nothing, so what ran comes before how well.
	fmt.Fprintf(out, "## Correctness first\n\n")
	deadNote := " — none dead"
	if len(dead) > 0 {
		deadNote = " — DEAD: " + strings.Join(dead, ", ")
	}
	fmt.Fprintf(out, "- **Executing:** %d/%d targets%s\n", len(last)-len(dead), len(last), deadNote)
	dictNote := ""
	if len(nodict) > 0 {
		dictNote = " — missing: " + strings.Join(nodict, ", ")
	}
	fmt.Fprintf(out, "- **Dictionaries:** %d/%d%s\n", len(last)-len(nodict), len(last), dictNote)
	fmt.Fprintf(out, "- **Total executions:** %s\n", comma(total))
	fmt.Fprintf(out, "- **Saturated (≥99%% of the run found nothing new):** %d/%d\n",
		len(badly), nsat)
	g := "none"
	if len(growing) > 0 {
		g = strings.Join(growing, ", ")
	}
	fmt.Fprintf(out, "- **Still climbing at the end (<50%%):** %s\n\n", g)

	fmt.Fprintf(out, "## Per target\n\n")
	fmt.Fprintln(out, "| target | dict | execs | cov | ft | corpus | last new edge | run spent saturated | new artifacts |")
	fmt.Fprintln(out, "|---|---|---:|---:|---:|---|---:|---:|---:|")
	var ts []string
	for t := range last {
		ts = append(ts, t)
	}
	sort.Strings(ts)
	for _, t := range ts {
		r := last[t]
		mark := " **DEAD**"
		if r.Alive {
			mark = ""
		}
		d := "—"
		if r.Dict {
			d = "yes"
		}
		satstr := "?"
		if r.SaturatedPct != nil {
			satstr = fmt.Sprintf("%s%%", trimF(*r.SaturatedPct))
			if *r.SaturatedPct >= 99 {
				satstr = "**" + satstr + "**"
			}
		}
		lne := "?"
		if r.LastNewEdgeAt != nil {
			lne = comma(*r.LastNewEdgeAt)
		}
		fmt.Fprintf(out, "| `%s`%s | %s | %s | %s | %s | %s → %s | %s | %s | %d |\n",
			t, mark, d, comma(r.ExecCount()), intOrQ(r.Cov), intOrQ(r.Ft),
			comma(r.CorpusBefore), comma(r.CorpusAfter), lne, satstr,
			r.ArtifactsAfter-r.ArtifactsBefore)
	}

	fmt.Fprintf(out, "\n## What to change next\n\n")
	if len(dead) > 0 {
		fmt.Fprintf(out, "1. **%d target(s) executed nothing.** Nothing else in this "+
			"report is meaningful for them: %s\n", len(dead), strings.Join(dead, ", "))
	}
	if len(badly) > 0 {
		fmt.Fprintf(out, "1. **%d target(s) spent ≥99%% of the run finding nothing.** "+
			"That compute is free to reallocate — either shorten them or give them "+
			"something new to chew on (dictionary, seeds, larger max_len).\n", len(badly))
		fmt.Fprintf(out, "   %s\n", strings.Join(badly, ", "))
	}
	if len(nodict) > 0 {
		fmt.Fprintf(out, "1. **No dictionary:** %s. For a structured "+
			"format that is usually the whole explanation for early saturation.\n",
			strings.Join(nodict, ", "))
	}
	if len(growing) > 0 {
		fmt.Fprintf(out, "1. **Starved, not saturated:** %s were still "+
			"finding new edges when the clock ran out. Give them more time first.\n",
			strings.Join(growing, ", "))
	}
	fmt.Fprintln(out)
	return 0
}

// CompareCampaigns puts two record files side by side.
func CompareCampaigns(out io.Writer, oldPath, newPath string, oldR, newR []CampaignRecord) int {
	o, n := latestCampaign(oldR), latestCampaign(newR)
	fmt.Fprintf(out, "# Campaign comparison\n\n")
	fmt.Fprintf(out, "**Before:** `%s`  \n**After:** `%s`\n\n", oldPath, newPath)
	// Said before the table, not after: a reader who takes the cov column at
	// face value across two builds has already drawn the wrong conclusion.
	fmt.Fprintf(out, "Coverage counters are only comparable across the *same build*. If the "+
		"builds differ, treat the cov column as indicative and the saturation "+
		"column as the real signal.\n\n")
	fmt.Fprintln(out, "| target | cov before | cov after | Δcov | sat before | sat after | Δsat |")
	fmt.Fprintln(out, "|---|---:|---:|---:|---:|---:|---:|")

	seen := map[string]bool{}
	var ts []string
	for t := range o {
		seen[t] = true
		ts = append(ts, t)
	}
	for t := range n {
		if !seen[t] {
			ts = append(ts, t)
		}
	}
	sort.Strings(ts)
	for _, t := range ts {
		a, b := o[t], n[t]
		d := "—"
		if a.Cov != nil && b.Cov != nil {
			d = signed(*b.Cov - *a.Cov)
		}
		ds := "—"
		if a.SaturatedPct != nil && b.SaturatedPct != nil {
			ds = fmt.Sprintf("%+.1f", *b.SaturatedPct-*a.SaturatedPct)
		}
		fmt.Fprintf(out, "| `%s` | %s | %s | %s | %s | %s | %s |\n",
			t, intOrDash(a.Cov), intOrDash(b.Cov), d,
			floatOrDash(a.SaturatedPct), floatOrDash(b.SaturatedPct), ds)
	}
	fmt.Fprintln(out)
	return 0
}

func orQ(s string) string {
	if s == "" {
		return "?"
	}
	return s
}

func intOrQ(v *int) string {
	if v == nil {
		return "?"
	}
	return fmt.Sprint(*v)
}

func intOrDash(v *int) string {
	if v == nil {
		return "—"
	}
	return fmt.Sprint(*v)
}

func floatOrDash(v *float64) string {
	if v == nil {
		return "—"
	}
	return trimF(*v)
}

func signed(n int) string {
	if n < 0 {
		return "-" + comma(-n)
	}
	return "+" + comma(n)
}

// trimF renders a float the way the record carries it: an integral value keeps
// no decimal point, matching how the number was written.
func trimF(f float64) string {
	s := fmt.Sprintf("%g", f)
	return s
}

package finalreport

import (
	"strings"
	"testing"
)

func soakData() RenderInputs {
	d := Data{
		Generated: "2026-08-28 21:49:31 CEST",
		Workspaces: map[string]WorkspaceData{
			"ws-add": {CorpusTotal: 1108889, Targets: map[string]TargetRow{
				"jsonb_fuzzer": {Log: LogStats{Execs: 117229235, NewUnits: 593},
					Artifacts: map[string]int{"crash": 946}},
			}},
		},
		Findings: Findings{
			Total:      25,
			ByCategory: map[string]int{"storage engine": 8, "PostgreSQL core": 7},
			ByTarget:   map[string]int{"spi_query_fuzzer": 5, "datetime_fuzzer": 1},
			Systemic:   7, Unattr: 2, Other: 5,
		},
		Masked: Masked{Degraded: make([]Degraded, 157)},
	}
	return RenderInputs{Data: d}
}

// THE ARCHIVED NUMBERS, not today's.
//
// A past run's report must render from the data.json it shipped. The findings
// corpus keeps moving -- a run archived on 2026-08-28 counted eight
// storage-engine findings where the same directory gives seven today -- so
// re-deriving would quietly restate what that run found.
func TestMarkdownRendersTheArchivedCounts(t *testing.T) {
	var b strings.Builder
	if err := RenderMarkdown(&b, soakData()); err != nil {
		t.Fatal(err)
	}
	got := b.String()
	for _, want := range []string{
		"**25 distinct findings, triaged.**",
		"| storage engine | 8 |",
		"| `spi_query_fuzzer` | 5 |",
		"1,108,889",   // the corpus, grouped
		"117,229,235", // the executions
		"2026-08-28 21:49:31 CEST",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the report never says %q", want)
		}
	}
	// The distinction the whole report exists to keep.
	if !strings.Contains(got, "An artifact is not a finding") {
		t.Error("the artifact-versus-finding warning is missing")
	}
}

// BIGGEST FIRST, and stable on a tie, so the table does not reshuffle between
// renders of the same data.
func TestMarkdownOrdersByCount(t *testing.T) {
	var a, b strings.Builder
	in := soakData()
	in.Data.Findings.ByCategory = map[string]int{"z": 3, "a": 3, "m": 9}
	if err := RenderMarkdown(&a, in); err != nil {
		t.Fatal(err)
	}
	if err := RenderMarkdown(&b, in); err != nil {
		t.Fatal(err)
	}
	if a.String() != b.String() {
		t.Fatal("two renders of one input differ; the tables reshuffle")
	}
	s := a.String()
	im, ia, iz := strings.Index(s, "| m |"), strings.Index(s, "| a |"), strings.Index(s, "| z |")
	if !(im < ia && ia < iz) {
		t.Errorf("order is m(9), a(3), z(3) by count then name; got %d %d %d", im, ia, iz)
	}
}

// A run with no coverage in its own archive shows none, rather than borrowing
// the coverage of whatever the host measured last.
func TestMarkdownOmitsAbsentCoverage(t *testing.T) {
	var b strings.Builder
	if err := RenderMarkdown(&b, soakData()); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), "## Coverage") {
		t.Error("a coverage section rendered with no union to render")
	}
}

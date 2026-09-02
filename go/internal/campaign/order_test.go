package campaign

import (
	"reflect"
	"testing"
)

// The failure this ordering was written to fix: a target that has not run
// recently must not be pushed further down for not having run.
//
// Each target's LATEST value is what counts, wherever in the series it sits --
// a soak slice writes a row for one target, so "the last four rows" scores
// four targets and zeroes the other nineteen.
func TestProductivityUsesEachTargetsLatestRow(t *testing.T) {
	rows := []SeriesNewUnits{
		{WS: "ws", NewUnits: map[string]int{"regex_fuzzer": 900, "spi_query_fuzzer": 800, "jsonb_fuzzer": 1}},
		// Four later single-target slices. Under a "last four rows" reading,
		// regex and spi_query would score zero and fall to the tiebreak.
		{WS: "ws", NewUnits: map[string]int{"jsonb_fuzzer": 2}},
		{WS: "ws", NewUnits: map[string]int{"jsonb_fuzzer": 3}},
		{WS: "other", NewUnits: map[string]int{"regex_fuzzer": 999999}},
	}
	latest := LatestNewUnits(rows, "ws")
	got := ByProductivity([]string{"jsonb_fuzzer", "regex_fuzzer", "spi_query_fuzzer"}, latest)
	want := []string{"regex_fuzzer", "spi_query_fuzzer", "jsonb_fuzzer"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("want %v, got %v", want, got)
	}
	if latest["regex_fuzzer"] != 900 {
		t.Errorf("another workspace's rows must not leak in: got %d", latest["regex_fuzzer"])
	}
}

// Ties break alphabetically so the order is deterministic.
func TestProductivityTiesBreakAlphabetically(t *testing.T) {
	got := ByProductivity([]string{"c", "a", "b"}, map[string]int{})
	if !reflect.DeepEqual(got, []string{"a", "b", "c"}) {
		t.Errorf("unranked targets must sort alphabetically, got %v", got)
	}
}

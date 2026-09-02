package campaign

import (
	"sort"
)

// ByProductivity orders targets most-productive-first, so an interrupted cycle
// spends its time where the finding is.
//
// EACH TARGET'S MOST RECENT VALUE, not "the last N rows".
//
// A round writes one row covering all 23 targets, so four rows used to mean
// four rounds of every target. A SOAK SLICE writes a row covering ONE target,
// so the same four rows now cover four targets and every other target scores
// zero and falls to the alphabetical tiebreak.
//
// That was self-reinforcing: a target that runs gets a row, sorts high, and
// runs again, while a target that has not run stays at zero and keeps waiting.
// The ordering rewarded recency and starved everything else -- regex_fuzzer sat
// at position 18 of 23 and spi_query at 21, both immediately after being
// repaired, which is exactly when they most needed the time.
//
// Walking the whole series and keeping each target's LATEST figure is robust to
// the row shape, so rounds and slices can both feed it.
//
// Ties break alphabetically, so the order is deterministic.
func ByProductivity(targets []string, latest map[string]int) []string {
	out := append([]string(nil), targets...)
	sort.SliceStable(out, func(i, j int) bool {
		a, b := latest[out[i]], latest[out[j]]
		if a != b {
			return a > b
		}
		return out[i] < out[j]
	})
	return out
}

// LatestNewUnits reduces a series to each target's most recent new_units count
// for one workspace.
func LatestNewUnits(rows []SeriesNewUnits, ws string) map[string]int {
	out := map[string]int{}
	for _, r := range rows {
		if r.WS != ws {
			continue
		}
		for t, v := range r.NewUnits {
			out[t] = v // later rows overwrite earlier ones
		}
	}
	return out
}

// SeriesNewUnits is the slice of a ratchet series row this ordering needs.
type SeriesNewUnits struct {
	WS       string         `json:"ws"`
	NewUnits map[string]int `json:"new_units"`
}

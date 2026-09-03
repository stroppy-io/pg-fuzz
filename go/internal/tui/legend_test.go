package tui

import (
	"strings"
	"testing"
)

// THE KEY MUST RUN IN THE ORDER OF WHAT IT EXPLAINS.
//
// The port sorted the legend items, and sorted them by the rendered string --
// so by the two-letter CODE rather than by the target. The grid's columns are
// in target order, so the key beneath it ran in a different order from the
// columns it was there to decode, and had to be read by scanning. The Python
// this replaces iterated its CODES table in order and did not sort.
func TestLegendKeepsTheGridsOrder(t *testing.T) {
	targets := []string{
		"xlogreader_fuzzer", "backend_types_fuzzer", "jsonb_fuzzer",
	}
	lines := Legend(targets, 200)
	if len(lines) == 0 {
		t.Fatal("no legend")
	}
	joined := strings.Join(lines, "")

	var at []int
	for _, want := range []string{"xlogreader", "backend_types", "jsonb"} {
		i := strings.Index(joined, want)
		if i < 0 {
			t.Fatalf("%q missing from the legend: %q", want, joined)
		}
		at = append(at, i)
	}
	for i := 1; i < len(at); i++ {
		if at[i] < at[i-1] {
			t.Errorf("the legend reordered its entries; the grid's columns are "+
				"in the given order and the key must match:\n  %s", joined)
			break
		}
	}
}

// Every target given gets an entry: a key that silently drops a column is
// worse than no key.
func TestLegendCoversEveryTarget(t *testing.T) {
	targets := []string{"a_fuzzer", "b_fuzzer", "c_fuzzer", "d_fuzzer"}
	joined := strings.Join(Legend(targets, 40), "")
	for _, want := range []string{"a", "b", "c", "d"} {
		if !strings.Contains(joined, " "+want) {
			t.Errorf("%q is not in the legend: %q", want, joined)
		}
	}
}

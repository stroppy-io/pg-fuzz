package tui

import (
	"strings"
	"testing"

	"pgfuzz/internal/term"
)

// A CLEAN ROUND MUST NOT ERASE EARLIER REPRODUCERS FROM THE GRID.
//
// The cell was reset on every round bump and then accumulated only that
// round's artifacts, while the header and the repro column accumulated across
// the whole campaign. From round 2 the grid could be entirely clean while the
// header read "reproducers 12" and a row read 12 -- with no cell saying where.
func TestCellShowsTheTotalAndColoursByThisRound(t *testing.T) {
	row := Row{
		Built: true,
		Cells: map[string]Cell{
			// Found in an earlier round, nothing new this one.
			"a_fuzzer": {Swept: true, ArtifactsAll: 3, Artifacts: 0, Round: 2},
			// Found again this round.
			"b_fuzzer": {Swept: true, ArtifactsAll: 5, Artifacts: 2, Round: 2},
		},
	}

	txt, colour := cell(row, "a_fuzzer", 3)
	if !strings.Contains(txt, "3") {
		t.Errorf("carried-over reproducers vanished from the cell: %q", txt)
	}
	if colour == term.Red {
		t.Error("a round that found nothing is coloured as though it had")
	}

	txt, colour = cell(row, "b_fuzzer", 3)
	if !strings.Contains(txt, "5") {
		t.Errorf("cell shows %q, want the running total 5", txt)
	}
	if colour != term.Red {
		t.Error("a round that found something is not marked")
	}
}

// A swept target with nothing found still reads as swept, not as untouched.
func TestCellSweptWithNothingFound(t *testing.T) {
	row := Row{Built: true, Cells: map[string]Cell{
		"a_fuzzer": {Swept: true, Round: 1},
	}}
	txt, _ := cell(row, "a_fuzzer", 3)
	if strings.TrimSpace(txt) == "" {
		t.Error("a swept target renders blank, like one that never ran")
	}
}

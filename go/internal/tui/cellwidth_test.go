package tui

import "testing"

// A FULLSCREEN WINDOW SHOULD GET A ROOMIER GRID.
//
// The Python widened the cells to fill the space left after the row label and
// the tail columns; the port used the minimum unconditionally, so the grid
// stayed the same small thing in the corner of a 200-column window.
func TestCellWidthGrowsWithTheWindow(t *testing.T) {
	const targets = 23

	narrow := CellWidth(100, targets)
	wide := CellWidth(240, targets)

	if narrow != cellW {
		t.Errorf("a narrow window gave %d, want the minimum %d", narrow, cellW)
	}
	if wide <= narrow {
		t.Errorf("a wide window gave %d, no wider than a narrow one's %d", wide, narrow)
	}
}

// NEVER NARROWER THAN THE MINIMUM, so numbers cannot truncate -- including on
// a window too small to hold the grid at all, where the arithmetic goes
// negative.
func TestCellWidthNeverBelowTheMinimum(t *testing.T) {
	for _, cols := range []int{0, 1, 40, 80} {
		if got := CellWidth(cols, 23); got < cellW {
			t.Errorf("CellWidth(%d, 23) = %d, below the minimum %d", cols, got, cellW)
		}
	}
	// No targets must not divide by zero.
	if got := CellWidth(200, 0); got < cellW {
		t.Errorf("CellWidth(200, 0) = %d", got)
	}
}

// AND CAPPED, because past a point a wider cell is just a sparser screen.
func TestCellWidthIsCapped(t *testing.T) {
	if got := CellWidth(10000, 1); got != 6 {
		t.Errorf("CellWidth on an enormous window = %d, want the cap 6", got)
	}
}

// The grid must actually FIT: label plus every cell plus the tail columns
// within the window, or the rows wrap and the whole layout collapses.
func TestGridFitsTheWindowItWasSizedFor(t *testing.T) {
	for _, cols := range []int{100, 140, 200, 240} {
		w := CellWidth(cols, 23)
		used := gridLabelW + 23*w + gridTailW
		if used > cols && w > cellW {
			t.Errorf("at %d columns the grid takes %d; it was widened past the window",
				cols, used)
		}
	}
}

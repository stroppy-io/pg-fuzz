package tui

import (
	"fmt"
	"sort"

	"pgfuzz/internal/term"
)

// THE COMPONENT VIEW, reachable from the grid again.
//
// The Python swapped the grid's rows for core / ext: / plugin: components at
// identical cell geometry, marking the live target and drawing swept-this-
// round in green, reusing the row state it already held rather than rescanning.
//
// internal/breakdown was ported and `pgfuzz breakdown -w <ws>` prints a table,
// but it is a separate command: no live marker, no swept state, and nothing on
// the dashboard reaches it. A campaign running now cannot be asked which
// component its crashes are coming from without leaving the dashboard.

// BreakdownRow is one component's crash counts across the targets.
type BreakdownRow struct {
	Component string
	// PerTarget is the count for each target, so the row lines up with the
	// grid's columns.
	PerTarget map[string]int
	Total     int
}

// drawBreakdown renders the component rows at the grid's geometry.
func drawBreakdown(s *term.Screen, m Model, sel int) int {
	if len(m.Breakdown) == 0 {
		s.Line(4, term.Dim+"no component breakdown yet -- it is built from "+
			"the crash logs a slice writes, so a campaign that has not "+
			"crashed has none"+term.Reset)
		return 6
	}
	const nameW = 17
	w := CellWidth(s.Cols, len(m.Targets)) - 1

	var head string
	head = pad(2+nameW) + ""
	for _, t := range m.Targets {
		head += " " + center(Code(t), w)
	}
	head += "   total"
	s.Line(4, term.Bold+head+term.Reset)

	row := 5
	for _, b := range m.Breakdown {
		if row >= s.Rows-2 {
			break
		}
		line := "  " + rpad(b.Component, nameW)
		for _, t := range m.Targets {
			n := b.PerTarget[t]
			switch {
			case n == 0:
				line += " " + center("·", w)
			case n >= 100:
				line += " " + rjust("++", w)
			default:
				line += " " + rjust(fmt.Sprint(n), w)
			}
		}
		line += "   " + rjust(fmt.Sprint(b.Total), 5)
		s.Line(row, line)
		row++
	}
	return row + 1
}

// SortBreakdown orders components by total, biggest first, then by name so a
// tie does not reshuffle between frames.
func SortBreakdown(rows []BreakdownRow) {
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Total != rows[j].Total {
			return rows[i].Total > rows[j].Total
		}
		return rows[i].Component < rows[j].Component
	})
}

func pad(n int) string {
	out := make([]byte, n)
	for i := range out {
		out[i] = ' '
	}
	return string(out)
}

func rpad(s string, w int) string {
	if len(s) >= w {
		return s[:w]
	}
	return s + pad(w-len(s))
}

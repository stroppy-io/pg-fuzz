package tui

import (
	"fmt"
	"strings"
	"time"

	"pgfuzz/internal/term"
)

// View is which screen is showing.
type View int

const (
	Grid View = iota
	Detail
)

// THE LAYOUT IS THE OLD DASHBOARD'S, deliberately.
//
// It was arrived at over a long campaign and every part of it answers a
// question somebody actually had at 3am. Reinventing it produced a grid that
// was missing the things that made it useful: what is happening RIGHT NOW,
// which workspaces are built, how big each corpus is and whether it is still
// growing, what the coverage build measured, and which commit any of this is
// against.
//
//	PHASE   round N   built b/n   reproducers t   elapsed HhMMm
//	NOW: <what is happening this second>
//
//	                   bt br cf ...   rnd this  total   corpus   +new    cov   commit
//	> gt-pg17          ·  ●  ··       r1  7/23      0      1.1k   +204   12.3%  61636c17b3
//
// cells:  ·· not built   × build failed   (blank) idle   ◐ building
//
//	● fuzzing   · swept clean   N reproducers
const cellW = 3 // content is cellW-1; each column is a leading space plus that

// Draw renders one frame.
func Draw(s *term.Screen, m Model, v View, sel int, rows, cols int) {
	s.Reset(rows, cols)
	drawHeader(s, m)
	switch v {
	case Detail:
		drawDetail(s, m, sel)
	default:
		drawPanels(s, m, drawGrid(s, m, sel))
	}
	drawFooter(s, m, v)
}

func drawHeader(s *term.Screen, m Model) {
	state := term.Dim + "not running" + term.Reset
	if m.Live {
		state = term.Green + "running" + term.Reset
	}
	el := m.Elapsed()
	s.Line(1, fmt.Sprintf("%s%s%s  %s   %s   round %d   built %d/%d   reproducers %d   elapsed %dh%02dm",
		term.Bold, m.Slug, term.Reset, state,
		phaseLabel(m), m.Round, m.Built, len(m.Rows), m.TotalArts,
		int(el.Hours()), int(el.Minutes())%60))
	s.Line(2, term.Dim+"NOW: "+term.Reset+m.Activity)
}

func phaseLabel(m Model) string {
	if len(m.Building) > 0 {
		return term.Yellow + m.Phase + term.Reset
	}
	if m.Sealed {
		return m.Phase + term.Dim + " (sealed)" + term.Reset
	}
	return m.Phase
}

func drawGrid(s *term.Screen, m Model, sel int) int {
	if len(m.Rows) == 0 {
		s.Line(4, term.Dim+"no campaign here"+term.Reset)
		return 5
	}
	const nameW = 17
	w := cellW - 1

	// Column headings line up with the cells: the row is "> " plus a
	// 17-column name, and each cell is a leading space plus w.
	var head strings.Builder
	head.WriteString(strings.Repeat(" ", 2+nameW))
	for _, t := range m.Targets {
		head.WriteString(" " + center(Code(t), w))
	}
	for _, c := range tailCols {
		head.WriteString(" " + rjust(c.title, c.w))
	}
	// Padded to the sha width, so the label sits over the column it names.
	head.WriteString("  " + "commit" + strings.Repeat(" ", 4))
	s.Line(4, term.Bold+head.String()+term.Reset)

	row := 5
	for i, r := range m.Rows {
		if row >= s.Rows-2 {
			break
		}
		var b strings.Builder
		// The SELECTED row, distinct from the "> " live marker. j/k and the
		// arrows moved a selection nothing drew, so the keys looked broken.
		if i == sel {
			b.WriteString(term.Reverse)
		}
		// "> " marks the workspace that is working, so the eye finds it
		// without reading every row.
		if r.Running != "" || r.Building {
			b.WriteString(term.Green + "> " + term.Reset)
		} else {
			b.WriteString("  ")
		}
		fmt.Fprintf(&b, "%-*s", nameW, clipName(r.Name, nameW-1))
		for _, t := range m.Targets {
			text, colour := cell(r, t, w)
			b.WriteString(" " + colour + text + term.Reset)
		}
		for _, c := range tailCols {
			v := ""
			if r.Built {
				v = c.value(r, len(m.Targets))
			}
			b.WriteString(" " + rjust(v, c.w))
		}
		if r.SHA != "" {
			fmt.Fprintf(&b, "  %s%s%s", term.Dim, r.SHA, term.Reset)
		}
		if i == sel {
			b.WriteString(term.Reset)
		}
		s.Line(row, b.String())
		row++
	}
	return row + 1
}

// tailCols are the columns to the right of the grid.
//
// Header text and cell text come from ONE table, with one width each, because
// the two were hand-spaced separately before and drifted apart -- which is the
// whole of "the table looks off". A column cannot now be widened in one place
// and not the other.
var tailCols = []struct {
	title string
	w     int
	value func(r Row, ntargets int) string
}{
	{"rnd", 4, func(r Row, _ int) string { return "r" + fmt.Sprint(r.Round) }},
	{"swept", 6, func(r Row, n int) string { return fmt.Sprintf("%d/%d", r.Swept, n) }},
	{"repro", 6, func(r Row, _ int) string { return comma(r.Arts) }},
	// ZERO AND NOT-RECORDED ARE DIFFERENT STATES. A corpus of 0 means "no
	// slice has reported one yet", not "the corpus is empty", and printing 0
	// for both reads as a measured emptiness.
	{"corpus", 8, func(r Row, _ int) string {
		if r.Corpus == 0 {
			return "-"
		}
		return short(r.Corpus)
	}},
	{"+new", 7, func(r Row, _ int) string {
		if r.Swept == 0 {
			return "-"
		}
		return "+" + short(r.CorpusNew)
	}},
	{"cov", 6, func(r Row, _ int) string {
		if r.CovPct <= 0 {
			return "-"
		}
		return fmt.Sprintf("%.1f%%", r.CovPct)
	}},
	{"execs", 13, func(r Row, _ int) string { return comma(r.Execs) }},
}

// cell is the old dashboard's cell(), symbol for symbol.
//
// The ORDER is the substance. Building comes first because rebuilding an
// already-built workspace is still work in progress; a failed build is not the
// same as one that has not run; and a cell that never ran must never look like
// one that ran and found nothing -- that distinction is the whole reason a
// short round is worth reporting.
func cell(r Row, target string, w int) (string, string) {
	switch {
	case r.Building:
		return center("◐", w), term.Yellow
	case r.Failed:
		return center("×", w), term.Red
	case !r.Built:
		return center("··", w), term.Dim
	}
	if r.Running == target {
		return center("●", w), term.Yellow
	}
	c, ok := r.Cells[target]
	switch {
	case ok && c.Artifacts > 0:
		n := fmt.Sprint(c.Artifacts)
		if c.Artifacts >= 100 {
			n = "++"
		}
		return rjust(n, w), term.Red
	case ok && c.Swept:
		return center("·", w), term.Green
	}
	return strings.Repeat(" ", w), ""
}

func drawFooter(s *term.Screen, m Model, v View) {
	keys := "q quit   d detail   g grid   up/down select"
	if m.Err != "" {
		keys = term.Yellow + m.Err + term.Reset + "   " + keys
	}
	s.Line(s.Rows, term.Dim+keys+term.Reset)
}

// Legend spells the two-letter codes out. They keep the grid narrow and are
// meaningless on sight, and there is empty space below the grid.
//
// IN THE GRID'S OWN ORDER, which is the order it is given. The port sorted
// these, and sorted them by the rendered string -- so by the two-letter CODE,
// not by the target. A key whose rows run in a different order from the columns
// it explains is read by scanning, which is the one thing a key exists to
// avoid.
func Legend(targets []string, width int) []string {
	items := make([]string, 0, len(targets))
	for _, t := range targets {
		items = append(items, Code(t)+" "+strings.TrimSuffix(t, "_fuzzer"))
	}
	cw := 0
	for _, i := range items {
		if len(i)+2 > cw {
			cw = len(i) + 2
		}
	}
	per := (width - 10) / max(cw, 1)
	if per < 1 {
		per = 1
	}
	var lines []string
	var row []string
	for _, item := range items {
		row = append(row, item+strings.Repeat(" ", cw-len(item)))
		if len(row) == per {
			lines = append(lines, strings.TrimRight(strings.Join(row, ""), " "))
			row = nil
		}
	}
	if len(row) > 0 {
		lines = append(lines, strings.TrimRight(strings.Join(row, ""), " "))
	}
	return lines
}

func center(s string, w int) string {
	n := runeLen(s)
	if n >= w {
		return s
	}
	left := (w - n) / 2
	return strings.Repeat(" ", left) + s + strings.Repeat(" ", w-n-left)
}

func rjust(s string, w int) string {
	if n := runeLen(s); n < w {
		return strings.Repeat(" ", w-n) + s
	}
	return s
}

// runeLen, not len: ◐ · × ● are multi-byte, and padding by bytes shifts every
// column to the right of them.
func runeLen(s string) int { return len([]rune(s)) }

func clipName(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func comma(n int) string {
	s := fmt.Sprint(n)
	if n < 1000 {
		return s
	}
	var out []byte
	for i, c := range []byte(s) {
		if i > 0 && (len(s)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, c)
	}
	return string(out)
}

// short renders a count the way the old dashboard did: 1.1k rather than 1131,
// because the column is six wide and a corpus reaches seven figures.
func short(n int) string {
	switch {
	case n >= 1_000_000:
		return fmt.Sprintf("%.1fM", float64(n)/1e6)
	case n >= 1000:
		return fmt.Sprintf("%.1fk", float64(n)/1e3)
	}
	return fmt.Sprint(n)
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
func drawDetail(s *term.Screen, m Model, sel int) {
	if sel < 0 || sel >= len(m.Rows) {
		s.Line(4, term.Dim+"nothing selected"+term.Reset)
		return
	}
	r := m.Rows[sel]
	s.Line(4, term.Bold+r.Name+term.Reset)
	s.Line(5, fmt.Sprintf("%s%d of %d targets swept   %s executions   +%s inputs   %d artifacts%s",
		term.Dim, r.Swept, len(m.Targets), comma(r.Execs), comma(r.New), r.Arts, term.Reset))

	row := 7
	s.Line(row, term.Bold+fmt.Sprintf("  %-26s %14s %10s %8s", "TARGET", "EXECS", "NEW", "ARTS")+term.Reset)
	row++
	for _, t := range m.Targets {
		if row >= s.Rows-2 {
			break
		}
		c, ok := r.Cells[t]
		if !ok || !c.Swept {
			// Named anyway, and marked: a target missing from a detail view
			// is indistinguishable from one that does not exist.
			s.Line(row, fmt.Sprintf("  %-26s %s%14s%s", t, term.Yellow, "never ran", term.Reset))
			row++
			continue
		}
		mark := ""
		if c.Artifacts > 0 {
			mark = term.Red
		}
		s.Line(row, fmt.Sprintf("  %-26s %14s %10s %s%8d%s",
			t, comma(c.Execs), comma(c.NewUnits), mark, c.Artifacts, term.Reset))
		row++
	}
}

// drawPanels puts the growth curves and the machine's state under the grid.
// drawPanels is everything below the grid, in the order the old dashboard had
// it: how the corpora are growing, what the symbols mean, what the two-letter
// codes stand for, and whether the machine is healthy enough to keep going.
//
// The two keys are not decoration. The codes keep the grid narrow enough to fit
// 23 targets on a line and are meaningless on sight, and there is empty space
// below the grid, so they get spelled out where there is room.
func drawPanels(s *term.Screen, m Model, y int) int {
	if len(m.Growth) > 0 {
		s.Line(y, term.Dim+"growth (per round; scaled to the window shown, not to zero):"+term.Reset)
		y++
		for _, l := range m.Growth {
			if y >= s.Rows-2 {
				return y
			}
			s.Line(y, l)
			y++
		}
		y++
	}
	if len(m.Targets) > 0 && y < s.Rows-4 {
		s.Line(y, term.Dim+"targets:"+term.Reset)
		y++
		for _, l := range Legend(m.Targets, s.Cols) {
			if y >= s.Rows-2 {
				return y
			}
			s.Line(y, term.Dim+"  "+l+term.Reset)
			y++
		}
		y++
	}
	if y < s.Rows-2 {
		s.Line(y, term.Dim+"cells:  ·· not built   × build failed   (blank) idle   "+
			"◐ building   ● fuzzing   · swept   N reproducers"+term.Reset)
		y++
	}
	if m.Status != "" {
		style := term.Dim
		// The warning is the point of the line; dimming it would bury the one
		// thing that ends a campaign early.
		if strings.Contains(m.Status, "DISK LOW") ||
			strings.Contains(m.Status, "blocked on I/O") ||
			strings.Contains(m.Status, "oversubscribed") {
			style = term.Yellow
		}
		s.Line(y, style+m.Status+term.Reset)
		y++
	}
	return y
}

// Interval is how often the screen redraws.
//
// One second. The data changes when a slice finishes, which is minutes apart,
// so a faster loop spends CPU the campaign wants and produces an identical
// frame -- and this dashboard runs on the box doing the fuzzing.
const Interval = time.Second

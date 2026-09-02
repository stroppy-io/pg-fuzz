// Package term is just enough terminal for a dashboard.
//
// No dependency, deliberately. The reason this binary is worth shipping is
// that somebody can build and run it without a module proxy, and pulling in a
// TUI library to draw a grid of coloured dots would spend that for very
// little. Raw mode is two ioctls; the rest is escape codes.
//
// Linux only, which everything here is.
package term

import (
	"fmt"
	"os"
	"strings"
	"syscall"
	"unsafe"
)

// State is a saved terminal mode, to be restored on exit.
type State struct {
	fd  int
	old syscall.Termios
}

// MakeRaw puts the terminal in raw mode so keys arrive without Enter.
//
// Restore MUST run even on a panic or a signal: a process that exits without
// restoring leaves the user's shell with no echo and no line editing, which
// looks exactly like a hung terminal.
func MakeRaw(f *os.File) (*State, error) {
	fd := int(f.Fd())
	var old syscall.Termios
	if err := ioctl(fd, syscall.TCGETS, unsafe.Pointer(&old)); err != nil {
		return nil, err
	}
	raw := old
	raw.Iflag &^= syscall.IXON | syscall.ICRNL | syscall.BRKINT | syscall.INPCK | syscall.ISTRIP
	raw.Oflag &^= syscall.OPOST
	raw.Lflag &^= syscall.ECHO | syscall.ICANON | syscall.ISIG | syscall.IEXTEN
	raw.Cc[syscall.VMIN] = 0  // a read returns immediately...
	raw.Cc[syscall.VTIME] = 1 // ...or after 100ms, so the draw loop is not blocked
	if err := ioctl(fd, syscall.TCSETS, unsafe.Pointer(&raw)); err != nil {
		return nil, err
	}
	return &State{fd: fd, old: old}, nil
}

// Restore puts the terminal back.
func (s *State) Restore() {
	if s == nil {
		return
	}
	_ = ioctl(s.fd, syscall.TCSETS, unsafe.Pointer(&s.old))
}

type winsize struct{ Row, Col, X, Y uint16 }

// Size returns the terminal's rows and columns.
func Size(f *os.File) (rows, cols int) {
	var w winsize
	if err := ioctl(int(f.Fd()), syscall.TIOCGWINSZ, unsafe.Pointer(&w)); err != nil {
		return 24, 80
	}
	if w.Row == 0 || w.Col == 0 {
		return 24, 80
	}
	return int(w.Row), int(w.Col)
}

func ioctl(fd int, req uint, arg unsafe.Pointer) error {
	_, _, e := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(req), uintptr(arg))
	if e != 0 {
		return e
	}
	return nil
}

// Screen accumulates a frame and writes it in one go.
//
// One write per frame, not one per cell: a dashboard that writes as it draws
// tears visibly and, over ssh, spends more time in the terminal than in the
// data.
type Screen struct {
	b    strings.Builder
	Rows int
	Cols int

	// Plain renders with newlines instead of cursor positioning, for when
	// stdout is not a terminal. `pgfuzz tui | head` should show the dashboard,
	// not a single line of escape codes.
	Plain bool

	lastRow int
}

const (
	// Alternate screen, so quitting leaves the user's scrollback intact.
	EnterAlt = "\x1b[?1049h\x1b[?25l"
	LeaveAlt = "\x1b[?25h\x1b[?1049l"
)

// Reset starts a frame.
func (s *Screen) Reset(rows, cols int) {
	s.b.Reset()
	s.Rows, s.Cols = rows, cols
	if !s.Plain {
		s.b.WriteString("\x1b[H\x1b[2J")
	}
	s.lastRow = 0
}

// At moves the cursor. Rows and columns are 1-based, as the terminal counts.
func (s *Screen) At(row, col int) {
	if s.Plain {
		// Newlines for the gap since the last row written, so the shape of
		// the frame survives without cursor addressing.
		for ; s.lastRow < row; s.lastRow++ {
			if s.lastRow > 0 {
				s.b.WriteString("\n")
			}
		}
		return
	}
	fmt.Fprintf(&s.b, "\x1b[%d;%dH", row, col)
}

// Write puts text at the cursor, clipped to the terminal width.
func (s *Screen) Write(text string) { s.b.WriteString(text) }

// Line writes a whole row, truncated rather than wrapped -- a wrapped line
// shifts everything below it and makes a grid unreadable.
func (s *Screen) Line(row int, text string) {
	s.At(row, 1)
	s.b.WriteString(Clip(text, s.Cols))
	if s.Plain {
		s.lastRow = row
	}
}

// Flush writes the frame.
func (s *Screen) Flush(f *os.File) { f.WriteString(s.b.String()) }

// Colours, by name rather than number at the call site.
const (
	Reset  = "\x1b[0m"
	Bold   = "\x1b[1m"
	Dim    = "\x1b[2m"
	Red    = "\x1b[31m"
	Green  = "\x1b[32m"
	Yellow = "\x1b[33m"
	Blue   = "\x1b[34m"
	Cyan   = "\x1b[36m"
)

// Clip truncates to n visible columns, ignoring escape sequences.
//
// Counting bytes would cut in the middle of a colour code and leave the rest
// of the screen painted in it.
func Clip(s string, n int) string {
	if n <= 0 {
		return ""
	}
	var out strings.Builder
	vis := 0
	for i := 0; i < len(s); {
		if s[i] == 0x1b {
			j := i
			for j < len(s) && s[j] != 'm' {
				j++
			}
			if j < len(s) {
				j++
			}
			out.WriteString(s[i:j])
			i = j
			continue
		}
		if vis >= n {
			break
		}
		r := 1
		for i+r < len(s) && s[i+r]&0xC0 == 0x80 {
			r++ // a UTF-8 continuation byte is not a column
		}
		out.WriteString(s[i : i+r])
		i += r
		vis++
	}
	return out.String()
}

package gate

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// A GATE FAILURE HAS TO SURVIVE THE TERMINAL.
//
// The shell appended every per-round verdict to matrix-{starved,shortround,
// newub,regressed}.tsv, and the live event feed tailed those files. The port
// prints to stderr and writes nothing, so a regression detected in round 3 of
// an overnight campaign exists only in scrollback: the final report cannot
// mention it, the bundle cannot ship it, and nobody reading the slug
// afterwards can tell it happened.
//
// One JSONL beside the series, because that is where a campaign's other
// per-round facts already live and a reader that has one has the other.

// Failure is one gate's verdict on one workspace-round.
type Failure struct {
	At        string `json:"at"`
	RunID     string `json:"run_id,omitempty"`
	Round     int    `json:"round"`
	Workspace string `json:"ws"`
	// Gate names which check failed -- "starvation", "round-complete",
	// "ratchet". Named rather than numbered so a reader does not have to know
	// the order they run in.
	Gate   string `json:"gate"`
	Detail string `json:"detail,omitempty"`
}

// Record appends a failure. A campaign must not die because it could not write
// its own note, so the error is returned and callers may log it, but nothing
// here treats it as fatal.
func Record(path string, f Failure) error {
	if f.At == "" {
		f.At = time.Now().UTC().Format(time.RFC3339)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.Marshal(f)
	if err != nil {
		return err
	}
	fh, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer fh.Close()
	_, err = fh.Write(append(b, '\n'))
	return err
}

// ReadFailures reads them back. A missing file means no failure was recorded,
// which is not an error: most campaigns should produce none.
func ReadFailures(path string) ([]Failure, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []Failure
	for _, line := range splitLines(b) {
		if len(line) == 0 {
			continue
		}
		var f Failure
		if json.Unmarshal(line, &f) == nil {
			out = append(out, f)
		}
	}
	return out, nil
}

func splitLines(b []byte) [][]byte {
	var out [][]byte
	start := 0
	for i, c := range b {
		if c == '\n' {
			out = append(out, b[start:i])
			start = i + 1
		}
	}
	if start < len(b) {
		out = append(out, b[start:])
	}
	return out
}

// Package expect is the positive control: it asserts the harness can still
// find, and still report, defects it is known to reach.
//
// EVERY OTHER GATE ASKS WHETHER ANYTHING WENT WRONG. None of them asks whether
// the instrument would have noticed. A harness that stopped parsing UBSan
// output, or stopped carrying parsed sites into the census, passes starvation,
// slow-units, final-stats and round-complete without a murmur, ships a clean
// report, and goes on doing it -- because every one of those checks reads the
// same silence as health.
//
// So this fails in the opposite direction from the rest of the gates: here,
// ABSENCE IS THE FAILURE. It is the project's own rule turned to face the
// instrument rather than the subject.
package expect

import (
	"bufio"
	"os"
	"strings"

	"pgfuzz/internal/gate"
)

// Want is one finding the harness must still produce.
type Want struct {
	Function string   // the innermost frame; survives a rebase, unlike a line
	Scope    []string // workspace-name globs, as in the UBSan accept-list
	File     string   // what the census keys its signature on
	Class    string
	Ref      string
	Added    string
}

// Load reads the list. The format is the UBSan accept-list's, deliberately:
// one shape of file to learn, and the scope column means the same thing in
// both. The third column differs -- there it is prose describing the site,
// here it is the file the census will name -- so this has its own reader
// rather than overloading LoadAccepted's meaning.
func Load(path string) ([]Want, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []Want
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		c := strings.Split(line, "\t")
		if len(c) < 4 {
			continue
		}
		w := Want{
			Function: strings.TrimSpace(c[0]),
			Scope:    strings.Split(strings.TrimSpace(c[1]), ","),
			File:     strings.TrimSpace(c[2]),
			Class:    strings.TrimSpace(c[3]),
		}
		if len(c) > 4 {
			w.Ref = strings.TrimSpace(c[4])
		}
		if len(c) > 5 {
			w.Added = strings.TrimSpace(c[5])
		}
		out = append(out, w)
	}
	return out, sc.Err()
}

// InScope reuses the accept-list's matcher, so a glob cannot mean one thing in
// one file and something else in the other.
func (w Want) InScope(ws string) bool {
	return gate.InScope(gate.Accepted{Scope: w.Scope}, ws)
}

// Result is one row's verdict. Found and Reported are separate claims: the
// first can hold while the second does not, and that gap is precisely the
// regression where parsing still works and the reporting layer has come loose.
type Result struct {
	Want     Want
	Found    bool // the function fired in this run's logs
	Reported bool // the census made a signature naming its file
}

// OK is true when the harness both saw it and said so.
func (r Result) OK() bool { return r.Found && r.Reported }

// Check judges every in-scope row.
//
// seen is the set of functions that were the innermost frame of a UB report;
// reported is the set of file basenames the census named in its signatures.
// Rows out of scope for this workspace are not returned at all -- a row scoped
// to 16 and 17 is not evidence about a master build, and counting it as
// missing there would make the control fire on the wrong thing.
func Check(wants []Want, ws string, seen, reported map[string]bool) []Result {
	var out []Result
	for _, w := range wants {
		if !w.InScope(ws) {
			continue
		}
		out = append(out, Result{
			Want:     w,
			Found:    seen[w.Function],
			Reported: reported[w.File],
		})
	}
	return out
}

// Missing counts the rows that did not hold.
func Missing(rs []Result) int {
	n := 0
	for _, r := range rs {
		if !r.OK() {
			n++
		}
	}
	return n
}

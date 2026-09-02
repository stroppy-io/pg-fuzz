// Package plateau detects convergence on a TIME axis instead of a round axis.
//
// WHY THIS EXISTS
// ===============
// Rounds restart libFuzzer, and libFuzzer replays its entire corpus before it
// mutates anything. Measured across 42 target-rounds: 1,157s of replay against
// 4,010s of budget -- 28.9% of every round re-executing inputs whose coverage
// is already known, paid again every round. The restart also discards
// libFuzzer's in-memory state: the feature map, per-input energy, and the
// scheduling heuristics it builds deciding what is worth mutating.
//
// A continuous run pays replay once. But "has it stopped growing?" then has no
// round boundary to be evaluated at, so growth has to be measured against a
// SLIDING WINDOW of wall-clock time instead. That decoupling is an improvement
// in its own right: measurement cadence stops being tied to execution cadence.
//
// WHAT IT SAMPLES -- both live, neither requiring the fuzzer to stop
// -----------------------------------------------------------------
//
//	corpus    file count per workspace, straight off disk
//	coverage  libFuzzer's own `cov:` counter, which it prints on every NEW and
//	          pulse line. Edge coverage, free and continuous; no separate
//	          coverage run, no profdata, no container.
package plateau

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Sample is one point of a series.
type Sample struct {
	At time.Time
	V  int
}

// Growth is the relative % change against the oldest sample still inside the
// window, or nil when the window has not filled.
//
// Nil is not zero. A window that has not filled says nothing, and reporting it
// as "no growth" would declare a plateau the moment the watch starts.
func Growth(series []Sample, window time.Duration, now time.Time) *float64 {
	var old *int
	for _, s := range series {
		if now.Sub(s.At) >= window {
			v := s.V
			old = &v
		} else {
			break
		}
	}
	if old == nil || *old == 0 {
		return nil
	}
	g := float64(series[len(series)-1].V-*old) / float64(*old) * 100
	return &g
}

// Flat is the two-sided test. A DROP is not convergence, it is something
// breaking, so the margin is applied in both directions.
func Flat(g *float64, margin float64) bool {
	return g != nil && -margin < *g && *g < margin
}

var (
	reBannerP = regexp.MustCompile(`^-+ ([a-z0-9_]+_fuzzer) -+$`)
	reAnsiP   = regexp.MustCompile(`\x1b\[[0-9;]*m`)
	reCovP    = regexp.MustCompile(`\bcov: (\d+)`)
	reSoak    = regexp.MustCompile(`^soak-([a-z0-9_]+_fuzzer)\.log$`)
)

// ScanCov updates per-target edge coverage from newly appended log text, and
// returns the target the text ended inside.
func ScanCov(text, curTarget string, cov map[string]int) string {
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(reAnsiP.ReplaceAllString(line, ""))
		if m := reBannerP.FindStringSubmatch(line); m != nil {
			curTarget = m[1]
			continue
		}
		if curTarget == "" || !strings.Contains(line, "cov:") {
			continue
		}
		if m := reCovP.FindStringSubmatch(line); m != nil {
			v, _ := strconv.Atoi(m[1])
			if v > cov[curTarget] {
				cov[curTarget] = v
			}
		}
	}
	return curTarget
}

// LiveLog is one log worth reading, and the target it belongs to if the
// filename says.
type LiveLog struct {
	Path   string
	Target string // "" means the banners inside decide
}

// LiveLogs lists the logs a watch should read.
//
// Round logs interleave all targets into one file, so only the NEWEST is live
// and the target has to come from the banners inside it. Soak logs are one per
// target and all of them are live at once -- and the filename names the
// target, which is more reliable than a banner that may not have been flushed
// yet.
func LiveLogs(wsDir string, patterns []string) []LiveLog {
	ents, err := os.ReadDir(wsDir)
	if err != nil {
		return nil
	}
	var out []LiveLog
	for _, e := range ents {
		if m := reSoak.FindStringSubmatch(e.Name()); m != nil {
			out = append(out, LiveLog{filepath.Join(wsDir, e.Name()), m[1]})
		}
	}
	for _, pat := range patterns {
		if pat == "soak-" {
			continue
		}
		best, bestT := "", time.Time{}
		for _, e := range ents {
			n := e.Name()
			if !strings.HasPrefix(n, pat) || !strings.HasSuffix(n, ".log") {
				continue
			}
			fi, err := e.Info()
			if err != nil {
				continue
			}
			if best == "" || fi.ModTime().After(bestT) {
				best, bestT = filepath.Join(wsDir, n), fi.ModTime()
			}
		}
		if best != "" {
			out = append(out, LiveLog{best, ""})
		}
	}
	return out
}

// Credited is the number of files the cap has removed for a workspace,
// cumulative.
//
// A cap is MAINTENANCE, not the corpus shrinking on its own. Adding the
// cumulative total back keeps the window measuring organic growth: the removal
// lands in both ends of the comparison and cancels. In soak mode there is no
// replay phase to outgrow, so caps should not fire at all and this term stays
// constant -- which is exactly what it should do.
func Credited(ledger, ws string) int {
	f, err := os.Open(ledger)
	if err != nil {
		return 0
	}
	defer f.Close()
	n := 0
	dec := json.NewDecoder(f)
	for {
		var r struct {
			WS      string `json:"ws"`
			Removed int    `json:"removed"`
		}
		if err := dec.Decode(&r); err != nil {
			break
		}
		if r.WS == ws {
			n += r.Removed
		}
	}
	return n
}

// CorpusCount is the workspace's total input count, with capped files credited
// back.
func CorpusCount(wsDir, ledger, ws string) int {
	n := Credited(ledger, ws)
	ents, err := os.ReadDir(filepath.Join(wsDir, "corpus"))
	if err != nil {
		return n
	}
	for _, e := range ents {
		// Backups and scratch are NOT targets.
		if !e.IsDir() || !strings.HasSuffix(e.Name(), "_fuzzer") {
			continue
		}
		inner, err := os.ReadDir(filepath.Join(wsDir, "corpus", e.Name()))
		if err != nil {
			continue
		}
		n += len(inner)
	}
	return n
}

// LogTail reads only the bytes appended since last time.
//
// Keyed by INODE as well as path, because a sweep log can be rotated and
// recreated under the same name -- a stale offset into a fresh file would skip
// its beginning entirely.
type LogTail struct {
	state map[string]*tailState
}

type tailState struct {
	ino  uint64
	off  int64
	tail string
}

// NewLogTail makes a reader.
func NewLogTail() *LogTail { return &LogTail{state: map[string]*tailState{}} }

// Read returns the whole lines appended since the previous call.
func (t *LogTail) Read(path string) string {
	fi, err := os.Stat(path)
	if err != nil {
		return ""
	}
	var ino uint64
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		ino = st.Ino
	}
	ent := t.state[path]
	if ent == nil || ent.ino != ino || fi.Size() < ent.off {
		ent = &tailState{ino: ino}
		t.state[path] = ent
	}
	if fi.Size() == ent.off {
		return ""
	}
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	if _, err := f.Seek(ent.off, 0); err != nil {
		return ""
	}
	buf := make([]byte, fi.Size()-ent.off)
	n, _ := f.Read(buf)
	ent.off += int64(n)

	// A partial final line is held back, not parsed: half a "cov:" line is not
	// a coverage sample.
	data := ent.tail + string(buf[:n])
	lines := strings.Split(data, "\n")
	ent.tail = lines[len(lines)-1]
	return strings.Join(lines[:len(lines)-1], "\n")
}

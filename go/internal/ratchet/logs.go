package ratchet

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"time"
)

// Resolving which log a round is judged from.
//
// A gate that reads the wrong log gives a confident wrong answer, so this is
// spelled out rather than globbed.

var roundLogRe = regexp.MustCompile(`^sweep-round(\d+)\.log(\.gz)?$`)

// SweepLog returns the log for one round, or the NEWEST round's log when round
// is negative.
//
// NEWEST BY MTIME, not by round number. Round numbers restart with every
// campaign, so a workspace can hold round 7 from a fortnight ago beside round
// 3 from last night -- and "highest number" then picks the stale one.
//
// This is not hypothetical: the first full run of this gate reported 14 failed
// workspaces, including config_file_fuzzer at 5,656 against a 3,409,719 floor.
// The real round-3 figure was 3,245,012. Every one of those failures was this
// bug reading a log from three weeks earlier. The starvation gate disagreed,
// which is the only reason it was caught -- it takes its round explicitly.
func SweepLog(wsDir string, round int) string {
	if round >= 0 {
		for _, p := range []string{
			filepath.Join(wsDir, "sweep-round"+strconv.Itoa(round)+".log"),
			filepath.Join(wsDir, "sweep-round"+strconv.Itoa(round)+".log.gz"),
		} {
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
		return ""
	}
	ents, err := os.ReadDir(wsDir)
	if err != nil {
		return ""
	}
	best, bestT := "", time.Time{}
	for _, e := range ents {
		if !roundLogRe.MatchString(e.Name()) {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		if best == "" || fi.ModTime().After(bestT) {
			best, bestT = filepath.Join(wsDir, e.Name()), fi.ModTime()
		}
	}
	return best
}

// AllRounds lists the round numbers a workspace has a log for, ascending.
func AllRounds(wsDir string) []int {
	ents, err := os.ReadDir(wsDir)
	if err != nil {
		return nil
	}
	// DEDUPLICATED. A round often has both sweep-roundN.log and its .gz --
	// the compressor keeps the original until it is cleaned up -- and listing
	// the number twice makes every caller scan the same round twice. It cannot
	// change an answer, because SweepLog resolves the pair to one file either
	// way; it just doubles the work over 170 GB of logs.
	seen := map[int]bool{}
	var out []int
	for _, e := range ents {
		if m := roundLogRe.FindStringSubmatch(e.Name()); m != nil {
			n, err := strconv.Atoi(m[1])
			if err == nil && !seen[n] {
				seen[n] = true
				out = append(out, n)
			}
		}
	}
	sort.Ints(out)
	return out
}

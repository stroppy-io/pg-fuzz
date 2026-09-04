// Package logs reads what a fuzzing run actually did.
//
// Every gate in this tree parses the same libFuzzer output, and each one grew
// its own parser: the starvation check, the UBSan check, the slow-unit check,
// the ratchet and the TUI all scan for overlapping things in slightly
// different ways. That is four chances to disagree about whether a target ran,
// and they have disagreed.
//
// TWO NUMBERS THAT LOOK ALIKE AND ARE NOT
// =======================================
// `#N INITED` is where the corpus REPLAY finished. `#M DONE` is where the run
// finished. When M is close to N the slice spent its whole budget re-running
// inputs it already had and invented nothing -- while reporting a large
// execution count, which reads as the busiest target on the grid.
//
// And exec/s in a libFuzzer pulse line is CUMULATIVE -- total executions over
// elapsed seconds, not an instantaneous rate. Reading it as a rate produced
// several wrong conclusions here before anybody checked.
package logs

import (
	"bufio"
	"compress/gzip"
	"io"
	"math"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// Stats is one target's run.
type Stats struct {
	Target      string
	Inited      int  // executions when corpus replay finished
	Done        int  // executions when the run finished
	Execs       int  // executions: "Done N runs" summed, else the stat:: sum
	Partial     bool // Execs came from a progress line: a cut slice, a lower bound
	NewUnits    int  // stat::new_units_added
	SlowestUnit int  // stat::slowest_unit_time_sec
	PeakRSS     int
	Cov         int     // last `cov:` seen
	Ft          int     // last `ft:` seen
	Corpus      int     // last `corp:` count
	Timeout     int     // the -timeout the run was given
	Runs        int     // "Done N runs", summed across workers
	Seconds     int     // the LONGEST worker's wall clock, never the sum
	Rate        float64 // executions per second, cross-worker
	UB          []UBSite
	Crashes     []string

	// Banner is whether libFuzzer announced itself at all. Without it,
	// "died inside our own initialisation" and "ran and was killed before it
	// printed" are the same observation.
	Banner bool
	// Aborted is libFuzzer's own words for a corpus it could not use. These
	// are deliberately NOT suppressible: a target that aborted did not fuzz,
	// whatever a floor or an acknowledgement says.
	Aborted bool

	// avgRate is libFuzzer's own average, the fallback for a run stopped by
	// SIGTERM: it prints stats but no Done line, so without this the targets
	// the watchdog has to stop are exactly the ones with no rate, and their
	// floors become unverifiable.
	avgRate int

	// statExecs is the stat:: sum, kept apart from Execs because on an ASan
	// build it is printed TWICE per job -- LeakSanitizer reports at exit and
	// the block repeats -- so 16 jobs produce 32 blocks and the naive sum is
	// exactly 2x. It is the fallback, never the first choice.
	statExecs int

	// progressExecs is the highest #N libFuzzer printed on a progress line.
	// A LOWER BOUND FROM AN INTERRUPTED SLICE, never a total -- see Execs.
	progressExecs int
}

// UBSite is one UndefinedBehaviorSanitizer report.
type UBSite struct {
	Function string // the innermost frame: what the baseline keys on
	File     string
	Line     int
	Class    string // signed-overflow, shift, null-deref, ...
	Text     string
}

var (
	reInited = regexp.MustCompile(`^#(\d+)\s+INITED`)
	reDone   = regexp.MustCompile(`^#(\d+)\s+DONE`)
	reStat   = regexp.MustCompile(`^stat::([a-z_]+):\s*(\d+)`)
	reCovFt  = regexp.MustCompile(`cov: (\d+) ft: (\d+)`)
	// libFuzzer's per-line resident size: "rss: 980Mb". Read as well as the
	// final stats block, which a slice killed by the OOM killer never prints
	// -- precisely the slice whose memory growth somebody needs to see.
	reRSS      = regexp.MustCompile(`\brss:\s*(\d+)Mb\b`)
	reCorp     = regexp.MustCompile(`corp: (\d+)`)
	reTimeout  = regexp.MustCompile(`-timeout=(\d+)`)
	reRunsLine = regexp.MustCompile(`^Done (\d+) runs in (\d+) second`)
	reAvgRate  = regexp.MustCompile(`stat::average_exec_per_sec: *(\d+)`)
	reUB       = regexp.MustCompile(`([\w./-]+\.[ch]):(\d+):\d+: runtime error: (.+)`)
	// DEDUP_TOKEN, not the stack. The stack in these logs is bare addresses:
	// the container has no external symbolizer ("invalid path to external
	// symbolizer"), so every frame is +0x1234 and no function name appears.
	// DEDUP_TOKEN carries them anyway, innermost first, which is exactly what
	// the accept-list keys on -- and it is why that list keys on the function
	// rather than file:line, since tm2timestamp is timestamp.c:2012 on 17.7
	// and :2016 on 17.11.
	reDedup = regexp.MustCompile(`^DEDUP_TOKEN: ([A-Za-z_][A-Za-z0-9_]*)`)
	reCrash = regexp.MustCompile(`^(?:==\d+==)?ERROR: (\w+Sanitizer: [^\n]+)`)
	reTrap  = regexp.MustCompile(`^TRAP: failed Assert\("([^"]+)"\)`)
)

// Parse reads one run log.
func Parse(r io.Reader) Stats {
	var s Stats
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 256*1024), 8*1024*1024) // ASan reports are long
	var pendingUB *UBSite
	_ = pendingUB
	for sc.Scan() {
		line := strip(sc.Text())

		if strings.Contains(line, "Running with entropic") ||
			strings.Contains(line, "INFO: Seed:") ||
			strings.Contains(line, "INFO: Loaded ") {
			s.Banner = true
		}
		// libFuzzer's own words, and the ERROR PREFIX IS PART OF THEM.
		//
		// The comment here used to say "matched exactly" and the code did not.
		// libFuzzer prints a WARNING with almost the same wording whenever the
		// seed corpus is small:
		//
		//	WARNING: no interesting inputs were found so far. Is the code
		//	instrumented for coverage?
		//
		// It then fuzzes perfectly well. A bare Contains matched that warning,
		// so numeric_fuzzer -- 204,128 executions, two workers, both finishing
		// -- was reported as "libFuzzer aborted on the initial corpus, it never
		// fuzzed" and failed a healthy sweep item. Any target with a one-file
		// seed corpus could trip it, on any run.
		//
		// The fatal forms both carry "ERROR: libFuzzer: ". The warning does
		// not, which is the whole difference between a target that died and a
		// target that had not found anything YET.
		if strings.Contains(line, "ERROR: libFuzzer: a leak has been found in the initial corpus") ||
			strings.Contains(line, "ERROR: libFuzzer: no interesting inputs were found") {
			s.Aborted = true
		}
		// NOT the INITED line. "#1000 INITED" is where the corpus REPLAY
		// finished; the target has not entered the mutation loop yet, and
		// counting it as executions collapses "inited but never fuzzed" into
		// "fuzzed" -- one of the three startup states this package exists to
		// keep apart. Every later verb (NEW, REDUCE, pulse, DONE) is real
		// fuzzing.
		if m := reProgress.FindStringSubmatch(line); m != nil && m[2] != "INITED" {
			if n, err := strconv.Atoi(m[1]); err == nil && n > s.progressExecs {
				s.progressExecs = n
			}
		}
		if m := reInited.FindStringSubmatch(line); m != nil && s.Inited == 0 {
			s.Inited, _ = strconv.Atoi(m[1])
		}
		if m := reDone.FindStringSubmatch(line); m != nil {
			s.Done, _ = strconv.Atoi(m[1])
		}
		if m := reStat.FindStringSubmatch(line); m != nil {
			n, _ := strconv.Atoi(m[2])
			switch m[1] {
			case "number_of_executed_units":
				s.statExecs += n
			case "new_units_added":
				s.NewUnits += n
			case "slowest_unit_time_sec":
				if n > s.SlowestUnit {
					s.SlowestUnit = n
				}
			case "peak_rss_mb":
				if n > s.PeakRSS {
					s.PeakRSS = n
				}
			}
		}
		// The inline field as well as stat::peak_rss_mb; see reRSS.
		if m := reRSS.FindStringSubmatch(line); m != nil {
			if n, err := strconv.Atoi(m[1]); err == nil && n > s.PeakRSS {
				s.PeakRSS = n
			}
		}
		if m := reCovFt.FindStringSubmatch(line); m != nil {
			s.Cov, _ = strconv.Atoi(m[1])
			s.Ft, _ = strconv.Atoi(m[2])
		}
		if m := reCorp.FindStringSubmatch(line); m != nil {
			s.Corpus, _ = strconv.Atoi(m[1])
		}
		if m := reTimeout.FindStringSubmatch(line); m != nil && s.Timeout == 0 {
			s.Timeout, _ = strconv.Atoi(m[1])
		}
		if m := reRunsLine.FindStringSubmatch(line); m != nil {
			// Runs SUM across workers; seconds take the MAXIMUM. The workers
			// run concurrently, so their durations do not add -- summing both
			// yields per-worker throughput sitting beside a cross-worker
			// execution total, and comparing those two implied 9 to 88 hours
			// of work for a two-hour slice.
			n, _ := strconv.Atoi(m[1])
			sec, _ := strconv.Atoi(m[2])
			s.Runs += n
			if sec > s.Seconds {
				s.Seconds = sec
			}
		}
		if m := reAvgRate.FindStringSubmatch(line); m != nil && s.avgRate == 0 {
			s.avgRate, _ = strconv.Atoi(m[1])
		}

		// A UB report names its site on one line and its stack after it. The
		// baseline keys on the FUNCTION, not file:line -- tm2timestamp is
		// timestamp.c:2012 on 17.7 and :2016 on 17.11, so a key that shifts
		// under a minor release fails open on every branch at once.
		if m := reUB.FindStringSubmatch(line); m != nil {
			ln, _ := strconv.Atoi(m[2])
			pendingUB = &UBSite{
				File: base(m[1]), Line: ln,
				Class: classify(m[3]), Text: strings.TrimSpace(m[3]),
			}
			s.UB = append(s.UB, *pendingUB)
			continue
		}
		// Attach to the most recent site still missing a name, not to
		// whichever site was last seen. Reports interleave: a second
		// "runtime error" can arrive before the first one's DEDUP_TOKEN, and
		// pairing by recency alone left a third of the sites unattributed --
		// which the gate then reported as unattributable rather than as the
		// accepted function they belong to.
		if m := reDedup.FindStringSubmatch(line); m != nil {
			for i := len(s.UB) - 1; i >= 0; i-- {
				if s.UB[i].Function == "" {
					s.UB[i].Function = m[1]
					break
				}
			}
			pendingUB = nil
		}

		if m := reCrash.FindStringSubmatch(line); m != nil {
			s.Crashes = append(s.Crashes, m[1])
		}
		if m := reTrap.FindStringSubmatch(line); m != nil {
			s.Crashes = append(s.Crashes, "Assert("+m[1]+")")
		}
	}
	// EXECUTIONS COME FROM "Done N runs" WHEN THERE IS ONE.
	//
	// It is the target's own report of a completed run, one line per worker.
	// stat::number_of_executed_units looks equivalent and is not: on an ASan
	// build the stat block is emitted twice per job, so summing it doubles
	// every -add figure -- and that figure feeds the series, the ratchet floors
	// and the starvation gate. The old driver summed Done first for exactly
	// this reason and said so; the port summed stat:: unconditionally.
	if s.Runs > 0 {
		s.Execs = s.Runs
	} else {
		s.Execs = s.statExecs
	}

	// AND THE PROGRESS COUNTER WHEN THERE IS NEITHER.
	//
	// Both of the above are printed when a run ENDS. A slice cut mid-run --
	// which `-on-deadline cut` does by design at the end of a campaign's
	// clock -- prints neither, and the log then reported zero executions for
	// a target that had done hundreds of thousands. The starvation gate read
	// that zero and failed the round with "started but never fuzzed" about a
	// slice whose own log ends "#613474 REDUCE ... exec/s: 20449". A real CI
	// item went red on it, and the message sent the reader looking for a
	// broken harness that was working perfectly.
	//
	// Marked Partial, because a lower bound is not a total and must not be
	// treated as one: it is enough to say the target fuzzed, and not enough
	// to raise a ratchet floor against.
	if s.Execs == 0 && s.progressExecs > 0 {
		s.Execs = s.progressExecs
		s.Partial = true
	}

	// "Done N runs in M second" is PREFERRED for the rate too: it is the
	// target's own report. average_exec_per_sec is the fallback.
	if s.Seconds > 0 && s.Runs > 0 {
		s.Rate = math.Round(float64(s.Runs)/float64(s.Seconds)*100) / 100
	} else if s.avgRate > 0 {
		s.Rate = float64(s.avgRate)
	}
	return s
}

// ParseFile reads a log from disk.
// ParseFile reads one run log, gzipped or not.
//
// GZIPPED OR NOT is the substance. `pgfuzz tidy` compresses any log over 10 MB
// older than an hour, including the ones the runner writes -- and this read
// only plain files, so tidying a workspace silently blinded the ratchet, the
// starvation gate and the round-completeness gate at once. On the machine this
// was found on there were 113,705 .log.gz against 425 .log. The sweep parser
// already handled both; this half did not, and tidy's own header asserted that
// it did.
func ParseFile(path string) (Stats, error) {
	f, err := os.Open(path)
	if err != nil {
		return Stats{}, err
	}
	defer f.Close()

	var r io.Reader = f
	if strings.HasSuffix(path, ".gz") {
		zr, err := gzip.NewReader(f)
		if err != nil {
			return Stats{}, err
		}
		defer zr.Close()
		r = zr
	}
	return Parse(r), nil
}

// ReplayOnly reports whether the slice spent its budget re-running its corpus.
//
// The symptom is a LARGE number, which is why it went unseen: a target that
// replays 100,000 inputs and invents nothing reports 100,000 executions.
func (s Stats) ReplayOnly() bool {
	return s.Done > 0 && s.Inited > 0 && s.NewUnits == 0 && s.Done-s.Inited < s.Inited/100
}

var ansi = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func strip(s string) string { return ansi.ReplaceAllString(s, "") }

func base(p string) string {
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[i+1:]
	}
	return p
}

func classify(text string) string {
	switch {
	case strings.Contains(text, "signed integer overflow"),
		strings.Contains(text, "negation of"):
		return "signed-overflow"
	case strings.Contains(text, "shift exponent"):
		return "shift"
	case strings.Contains(text, "null pointer"):
		return "null-deref"
	case strings.Contains(text, "out of bounds"):
		return "out-of-bounds"
	}
	return "other"
}

// Startup is what a log says about whether the target ever became a fuzzer.
//
// THREE STATES, NOT TWO, and conflating them has cost this project twice in
// opposite directions: once failing all twelve builds of a campaign in four
// minutes, once letting four dead targets survive a whole campaign.
//
//   - Died: libFuzzer never spoke. The target aborted inside its own
//     initialisation, before the banner.
//   - Inited: it started and replayed, but never entered the mutation loop.
//   - Fuzzed: it executed.
//
// "No numbers" is NOT one of these: a log that could not be read says nothing
// about the run, and treating silence as any of the three is the mistake.
type Startup int

const (
	NoEvidence Startup = iota
	Died
	Inited
	Fuzzed
)

func (s Startup) String() string {
	switch s {
	case Died:
		return "died before libFuzzer started"
	case Inited:
		return "started but never fuzzed"
	case Fuzzed:
		return "fuzzed"
	}
	return "no evidence either way"
}

// Startup classifies a parsed log.
func (s Stats) Startup() Startup {
	switch {
	case s.Execs > 0 || s.Done > 0:
		return Fuzzed
	case s.Inited > 0 || s.Banner:
		return Inited
	case s.Aborted:
		return Died
	}
	return NoEvidence
}

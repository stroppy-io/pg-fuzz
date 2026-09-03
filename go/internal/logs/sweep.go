package logs

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"io"
	"math"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// A SWEEP log holds many targets in one file, delimited by the driver's own
// "fuzzing <target> for" lines, and each target may appear several times
// because its jobs run concurrently. Parsing it is not the same problem as
// parsing one run log, and conflating the two is how a gate ends up reading a
// number that is per-worker while comparing it against a cross-job total.

// SweepStats is one target's totals within a sweep.
type SweepStats struct {
	Execs    int     // stat::number_of_executed_units, SUMMED across jobs
	NewUnits int     // stat::new_units_added, summed
	Rate     float64 // executions per second, cross-job
}

var (
	// BOTH BANNERS. The shell printed "fuzzing <target> for <n>s"; the Go
	// sweep prints "---- <target> ---- (i/n)". ParseSweep matched only the
	// first, so a Go sweep log redirected to sweep-roundN.log parsed to an
	// EMPTY map -- and the ratchet, told to read a round log, reported
	// "nothing was checked" and exited 2. It failed closed, which is the right
	// direction, but the round was unjudgeable.
	reFuzzing = regexp.MustCompile(`fuzzing ([a-z_]+) for|^\s*-{4} ([a-z_]+_fuzzer) -{4}`)
	reExecs   = regexp.MustCompile(`stat::number_of_executed_units:\s*(\d+)`)
	reNew     = regexp.MustCompile(`stat::new_units_added:\s*(\d+)`)
	reAvg     = regexp.MustCompile(`stat::average_exec_per_sec: *(\d+)`)
	reRuns    = regexp.MustCompile(`^Done (\d+) runs in (\d+) second`)
)

// ParseSweep reads a sweep log, gzipped or not, and returns per-target totals.
//
// Counting from the log rather than from artifacts is deliberate and
// load-bearing: artifact counts measure how NOISY a target was, not whether it
// ran, and that confusion is why three dead targets survived multiple
// campaigns.
func ParseSweep(path string) (map[string]SweepStats, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var r io.Reader = f
	if strings.HasSuffix(path, ".gz") {
		zr, err := gzip.NewReader(f)
		if err != nil {
			return nil, err
		}
		defer zr.Close()
		r = zr
	}

	execs := map[string]int{}
	newUnits := map[string]int{}
	avg := map[string]int{}
	runs := map[string]int{}
	secs := map[string]int{}

	target := ""
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 256*1024), 8*1024*1024)
	for sc.Scan() {
		// A CHEAP PREFILTER BEFORE ANY REGEX.
		//
		// These logs are gigabytes of libFuzzer progress lines and only five
		// kinds of line matter. Running six regexes over every line made a
		// full-tree reseed take minutes where the shell's zgrep took seconds:
		// grep is fast because it rejects almost everything before it does any
		// real work, and so must this.
		raw := sc.Bytes()
		// THE PREFILTER HAS TO KNOW EVERY BANNER. It exists because running
		// six regexes over every line made a full-tree reseed take minutes
		// where zgrep took seconds -- but a filter that rejects a delimiter
		// makes the parser silently see no targets at all, which is how
		// adding the Go banner to the regex changed nothing.
		if !bytes.Contains(raw, []byte("stat::")) &&
			!bytes.Contains(raw, []byte("fuzzing ")) &&
			!bytes.Contains(raw, []byte("----")) &&
			!bytes.Contains(raw, []byte("Done ")) {
			continue
		}
		line := strip(sc.Text())
		if m := reFuzzing.FindStringSubmatch(line); m != nil {
			// Whichever alternative matched carries the name.
			if m[1] != "" {
				target = m[1]
			} else {
				target = m[2]
			}
			continue
		}
		if target == "" {
			continue
		}
		if m := reExecs.FindStringSubmatch(line); m != nil {
			n, _ := strconv.Atoi(m[1])
			execs[target] += n
			continue
		}
		if m := reNew.FindStringSubmatch(line); m != nil {
			n, _ := strconv.Atoi(m[1])
			newUnits[target] += n
			continue
		}
		if m := reAvg.FindStringSubmatch(line); m != nil {
			n, _ := strconv.Atoi(m[1])
			avg[target] += n
			continue
		}
		if m := reRuns.FindStringSubmatch(strings.TrimSpace(line)); m != nil {
			// runs SUM across jobs; seconds MAX.
			//
			// A target's jobs run CONCURRENTLY, so their durations do not add.
			// Summing both gave total_runs / (jobs x elapsed) -- per-worker
			// throughput -- while execs above is a true cross-job total. The
			// two were then compared against each other, and floor/rate
			// implied 9 to 88 hours of work for a two-hour slice on ten of
			// forty-six targets. Wall-clock elapsed is the largest single
			// job's, not the sum.
			n, _ := strconv.Atoi(m[1])
			s, _ := strconv.Atoi(m[2])
			runs[target] += n
			if s > secs[target] {
				secs[target] = s
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}

	out := make(map[string]SweepStats, len(execs))
	for t, e := range execs {
		out[t] = SweepStats{Execs: e, NewUnits: newUnits[t]}
	}
	for t := range out {
		st := out[t]
		// "Done N runs in M second" is PREFERRED: it is the target's own report
		// of a completed run. average_exec_per_sec is the fallback for a target
		// stopped by SIGTERM, which prints stats but no Done line -- without
		// it, exactly the targets the watchdog has to stop are the ones with no
		// rate, and their exec floors become unverifiable.
		if secs[t] > 0 && runs[t] > 0 {
			st.Rate = math.Round(float64(runs[t])/float64(secs[t])*100) / 100
		} else if avg[t] > 0 {
			st.Rate = float64(avg[t])
		}
		out[t] = st
	}
	return out, nil
}

// Regime is what makes two floors comparable, read from the log the round
// produced.
//
// Deliberately just the job count. A floor earned with four workers is not a
// claim about one, and comparing across that difference is how a healthy round
// gets failed -- or, worse, how a broken one passes.
type Regime struct {
	Jobs int
	Secs int // -max_total_time, recorded but not part of comparability
	// Dict is whether libFuzzer was given a dictionary.
	//
	// From the invocation, which is the only place it is stated. The report
	// carries a "Dictionaries: N/M" line whose field had no writer, so it read
	// 0/M forever -- and a structured-format target without one saturates
	// fast, which is a thing worth seeing rather than assuming.
	Dict bool
}

var (
	reJobsFlag = regexp.MustCompile(`-jobs=(\d+)`)
	reMaxTime  = regexp.MustCompile(`max_total_time=(\d+)`)
)

// ParseRegime reads the first invocation line of a log.
//
// The DEFAULT IS ONE JOB, and a log with no -jobs flag really did run with
// one. That default is only safe because the flag is always present when it is
// not one; if that stops being true, this reads a four-worker round as a
// single-worker one and every floor it earns is wrong by a factor of four.
func ParseRegime(path string) (Regime, error) {
	f, err := os.Open(path)
	if err != nil {
		return Regime{Jobs: 1}, err
	}
	defer f.Close()

	var r io.Reader = f
	if strings.HasSuffix(path, ".gz") {
		zr, err := gzip.NewReader(f)
		if err != nil {
			return Regime{Jobs: 1}, err
		}
		defer zr.Close()
		r = zr
	}

	reg := Regime{Jobs: 1}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 256*1024), 8*1024*1024)
	for sc.Scan() {
		if !bytes.Contains(sc.Bytes(), []byte("max_total_time=")) {
			continue
		}
		line := sc.Text()
		// The FIRST such line only, matching what the round was launched with.
		// Later lines belong to later targets and can differ.
		if m := reJobsFlag.FindStringSubmatch(line); m != nil {
			reg.Jobs, _ = strconv.Atoi(m[1])
		}
		if m := reMaxTime.FindStringSubmatch(line); m != nil {
			reg.Secs, _ = strconv.Atoi(m[1])
		}
		reg.Dict = strings.Contains(line, "-dict=")
		return reg, nil
	}
	return reg, sc.Err()
}

var reCovFtSweep = regexp.MustCompile(`\bcov: (\d+) ft: (\d+)`)

// Frontier is the edges reached and features distinguished at the END of a
// slice.
//
// libFuzzer prints "cov: N ft: M" on every progress line, and both were thrown
// away. They are the only per-slice view of the frontier there is: corpus size
// says how many inputs were KEPT, execs says how much work was done, and
// neither says whether the target is still finding new ground.
//
// The LAST occurrence, not the first: these grow monotonically within a slice,
// so the final value is the state the slice ended in. The first would record
// the state it inherited.
func Frontier(path string) (cov, ft int, ok bool) {
	f, err := os.Open(path)
	if err != nil {
		return 0, 0, false
	}
	defer f.Close()
	var r io.Reader = f
	if strings.HasSuffix(path, ".gz") {
		zr, err := gzip.NewReader(f)
		if err != nil {
			return 0, 0, false
		}
		defer zr.Close()
		r = zr
	}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 256*1024), 8*1024*1024)
	for sc.Scan() {
		// Same prefilter, same reason: "cov: " appears on progress lines only.
		if !bytes.Contains(sc.Bytes(), []byte("cov: ")) {
			continue
		}
		if m := reCovFtSweep.FindStringSubmatch(sc.Text()); m != nil {
			cov, _ = strconv.Atoi(m[1])
			ft, _ = strconv.Atoi(m[2])
			ok = true
		}
	}
	return cov, ft, ok
}

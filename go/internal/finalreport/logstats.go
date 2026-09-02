package finalreport

import (
	"bufio"
	"bytes"
	"os"
	"regexp"
	"sort"
	"strconv"
)

var (
	reAnsiLS  = regexp.MustCompile(`\x1b\[[0-9;]*m`)
	reInitedL = regexp.MustCompile(`^#(\d+)\s+INITED`)
	reDoneL   = regexp.MustCompile(`^#(\d+)\s+DONE`)
	reRunsL   = regexp.MustCompile(`^Done (\d+) runs in (\d+) second`)
	reExecsL  = regexp.MustCompile(`stat::number_of_executed_units:\s*(\d+)`)
	reNewL    = regexp.MustCompile(`stat::new_units_added:\s*(\d+)`)
	reErrL    = regexp.MustCompile(`(ERROR|FATAL):  ([a-z][a-z ]{4,40})`)
)

// ReadLogStats reads INITED, DONE, executions, new units and the commonest
// server errors from one target's slice log.
//
// #N INITED is where the corpus REPLAY finished; #M DONE is where the run
// finished. When M is close to N the slice spent its whole budget re-running
// inputs it already had and invented nothing -- while reporting a large
// execution count, which reads as the busiest target on the grid.
func ReadLogStats(path string) LogStats {
	st := LogStats{Errors: map[string]int{}}
	fi, err := os.Stat(path)
	if err != nil {
		return st
	}
	st.Bytes = fi.Size()
	f, err := os.Open(path)
	if err != nil {
		return st
	}
	defer f.Close()

	errs := map[string]int{}
	// FIRST-SEEN ORDER, kept alongside the counts.
	//
	// The five commonest are taken by a STABLE sort, so two errors with the
	// same count are ranked by which appeared in the log first. Breaking that
	// tie alphabetically instead changes which error the report shows -- and
	// "first seen" is at least a fact about the run, where alphabetical is a
	// fact about the alphabet.
	var order []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 256*1024), 8*1024*1024)
	for sc.Scan() {
		raw := sc.Bytes()
		// The same prefilter the sweep parser uses, for the same reason: these
		// files are gigabytes and five kinds of line matter.
		if !bytes.Contains(raw, []byte("stat::")) &&
			!bytes.Contains(raw, []byte("INITED")) &&
			!bytes.Contains(raw, []byte("DONE")) &&
			!bytes.Contains(raw, []byte("Done ")) &&
			!bytes.Contains(raw, []byte("ERROR:")) &&
			!bytes.Contains(raw, []byte("FATAL:")) {
			continue
		}
		line := reAnsiLS.ReplaceAllString(sc.Text(), "")
		if m := reInitedL.FindStringSubmatch(line); m != nil && st.Inited == nil {
			v, _ := strconv.Atoi(m[1])
			st.Inited = &v
		}
		if m := reDoneL.FindStringSubmatch(line); m != nil {
			v, _ := strconv.Atoi(m[1])
			st.Done = &v
		}
		if m := reRunsL.FindStringSubmatch(line); m != nil {
			r, _ := strconv.Atoi(m[1])
			s, _ := strconv.Atoi(m[2])
			st.Runs += r
			st.Seconds += s
		}
		if m := reExecsL.FindStringSubmatch(line); m != nil {
			v, _ := strconv.Atoi(m[1])
			st.Execs += v
		}
		if m := reNewL.FindStringSubmatch(line); m != nil {
			v, _ := strconv.Atoi(m[1])
			st.NewUnits += v
		}
		if m := reErrL.FindStringSubmatch(line); m != nil {
			k := trimSpace(m[2])
			if _, seen := errs[k]; !seen {
				order = append(order, k)
			}
			errs[k]++
		}
	}
	// The five commonest only. The whole distribution is a log in itself, and
	// the point here is the shape of what the target hit, not a census.
	type kv struct {
		K string
		V int
	}
	all := make([]kv, 0, len(errs))
	for _, k := range order {
		all = append(all, kv{k, errs[k]})
	}
	sort.SliceStable(all, func(i, j int) bool { return all[i].V > all[j].V })
	for i, e := range all {
		if i >= 5 {
			break
		}
		st.Errors[e.K] = e.V
	}
	return st
}

func trimSpace(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t') {
		s = s[:len(s)-1]
	}
	return s
}

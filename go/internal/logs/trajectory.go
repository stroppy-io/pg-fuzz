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

// The trajectory: what a run REACHED, and -- the part that matters -- what it
// GAINED.
//
// The peak coverage a run reaches is mostly a property of the corpus it
// started from: replay 300,000 saved inputs and you are at the ceiling before
// the fuzzer has done anything. The quality question is different and
// narrower: did coverage and features climb DURING this run?
//
// So the trajectory is measured from its own first datapoint, not from zero. A
// run with cov 6156 and cov_gained_in_run 0 did nothing; the same cov with a
// gain of 2276 did real work. Reporting only the first number flatters every
// run equally.

// Point is one libFuzzer progress line.
type Point struct {
	Execs, Cov, Ft, Corpus int
}

// Trajectory is what a run's progress lines say about it.
type Trajectory struct {
	Cov, Ft        int
	CovStart       int
	FtStart        int
	CovGainedInRun int
	FtGainedInRun  int
	CorpusEnd      int
	LastNewEdgeAt  int
	LastExecSeen   int
	SaturatedPct   *float64
}

var reProgress = regexp.MustCompile(`^#(\d+)\s+(\S+)\s+cov: (\d+) ft: (\d+) corp: (\d+)`)

// ReadTrajectory merges a log's progress lines.
func ReadTrajectory(path string) ([]Point, error) {
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
	var out []Point
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 256*1024), 8*1024*1024)
	for sc.Scan() {
		if !bytes.Contains(sc.Bytes(), []byte("cov: ")) {
			continue
		}
		m := reProgress.FindStringSubmatch(strip(sc.Text()))
		if m == nil {
			continue
		}
		n, _ := strconv.Atoi(m[1])
		cov, _ := strconv.Atoi(m[3])
		ft, _ := strconv.Atoi(m[4])
		corp, _ := strconv.Atoi(m[5])
		out = append(out, Point{n, cov, ft, corp})
	}
	return out, sc.Err()
}

// Summarise reduces a trajectory to the figures a report quotes.
func Summarise(traj []Point) Trajectory {
	if len(traj) == 0 {
		return Trajectory{}
	}
	// Ordered by EXECUTION COUNT, not by file order: with -jobs=N the workers
	// interleave, so the file is not chronological and "the first datapoint"
	// read off it would be whichever worker flushed first.
	ordered := make([]Point, len(traj))
	copy(ordered, traj)
	sortPoints(ordered)

	t := Trajectory{
		CovStart:  ordered[0].Cov,
		FtStart:   ordered[0].Ft,
		CorpusEnd: ordered[len(ordered)-1].Corpus,
	}
	best := -1
	for _, p := range ordered {
		if p.Cov > t.Cov {
			t.Cov = p.Cov
		}
		if p.Ft > t.Ft {
			t.Ft = p.Ft
		}
		if p.Execs > t.LastExecSeen {
			t.LastExecSeen = p.Execs
		}
		if p.Cov > best {
			best, t.LastNewEdgeAt = p.Cov, p.Execs
		}
	}
	t.CovGainedInRun = t.Cov - t.CovStart
	t.FtGainedInRun = t.Ft - t.FtStart
	if t.LastExecSeen > 0 {
		// How much of the run happened AFTER the last new edge. A target at
		// 99% spent the whole slice finding nothing, which is a decision about
		// where to put the next hour.
		v := math.Round(100*float64(t.LastExecSeen-t.LastNewEdgeAt)/float64(t.LastExecSeen)*10) / 10
		t.SaturatedPct = &v
	}
	return t
}

func sortPoints(p []Point) {
	for i := 1; i < len(p); i++ {
		for j := i; j > 0 && p[j].Execs < p[j-1].Execs; j-- {
			p[j], p[j-1] = p[j-1], p[j]
		}
	}
}

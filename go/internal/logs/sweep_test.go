package logs

import (
	"os"
	"path/filepath"
	"testing"
)

// A sweep log holds many targets, each possibly across several concurrent
// jobs. The two numbers that must not be added the same way are runs (summed)
// and seconds (maximum): the jobs run at the same time, so their durations do
// not add. Summing both gives per-worker throughput while the execution count
// beside it is a true cross-job total, and comparing those two implied 9 to 88
// hours of work for a two-hour slice.
func TestSweepSumsRunsButTakesTheLongestJob(t *testing.T) {
	log := `fuzzing binary_recv_fuzzer for 600s -jobs=4 -max_total_time=600
stat::number_of_executed_units: 1000
stat::new_units_added: 7
Done 1000 runs in 100 second(s)
stat::number_of_executed_units: 2000
stat::new_units_added: 3
Done 2000 runs in 100 second(s)
fuzzing regex_fuzzer for 600s
stat::number_of_executed_units: 50
stat::average_exec_per_sec: 17
`
	dir := t.TempDir()
	p := filepath.Join(dir, "sweep-round1.log")
	if err := os.WriteFile(p, []byte(log), 0o644); err != nil {
		t.Fatal(err)
	}
	per, err := ParseSweep(p)
	if err != nil {
		t.Fatal(err)
	}
	if got := per["binary_recv_fuzzer"].Execs; got != 3000 {
		t.Errorf("executions sum across jobs: want 3000, got %d", got)
	}
	// 3000 runs over the LONGEST job's 100 seconds, not over 200.
	if got := per["binary_recv_fuzzer"].Rate; got != 30 {
		t.Errorf("rate is total runs over the longest job: want 30, got %v", got)
	}
	if got := per["binary_recv_fuzzer"].NewUnits; got != 10 {
		t.Errorf("new units sum across jobs: want 10, got %d", got)
	}
	// average_exec_per_sec is the fallback for a target stopped by SIGTERM,
	// which prints stats but no Done line. Without it, exactly the targets the
	// watchdog has to stop are the ones with no rate.
	if got := per["regex_fuzzer"].Rate; got != 17 {
		t.Errorf("a target with no Done line falls back to the reported average: got %v", got)
	}
}

// The regime is what the round was LAUNCHED with, read from the log rather
// than passed in: a caller who forgets the flag would otherwise have every
// floor compared against the wrong regime, silently.
func TestRegimeComesFromTheLog(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "sweep-round1.log")
	os.WriteFile(p, []byte("run_fuzzer x -jobs=16 -max_total_time=1800\n"), 0o644)
	r, err := ParseRegime(p)
	if err != nil {
		t.Fatal(err)
	}
	if r.Jobs != 16 || r.Secs != 1800 {
		t.Errorf("want jobs=16 secs=1800, got %+v", r)
	}

	// A log with no flag really did run with one job.
	q := filepath.Join(dir, "sweep-round2.log")
	os.WriteFile(q, []byte("run_fuzzer x -max_total_time=600\n"), 0o644)
	if r, _ := ParseRegime(q); r.Jobs != 1 {
		t.Errorf("no -jobs flag means one job, got %d", r.Jobs)
	}
}

// The SINGLE-TARGET parser must produce the same rate as the sweep parser
// from the same numbers. It did not: the per-target path recorded no rate at
// all, so a campaign driven by the Go runner established zero rate floors
// while a sweep-driven one established twenty-three, and the difference was
// invisible in both outputs.
func TestSingleTargetParserAgreesWithTheSweepParser(t *testing.T) {
	const body = `Running: /out/x_fuzzer -jobs=4 -max_total_time=600
#24481	INITED cov: 1189 ft: 6858 corp: 1604/497Kb exec/s: 6120 rss: 60Mb
stat::number_of_executed_units: 1000
stat::new_units_added:          7
Done 1000 runs in 100 second(s)
stat::number_of_executed_units: 2000
stat::new_units_added:          3
Done 2000 runs in 100 second(s)
`
	dir := t.TempDir()
	one := filepath.Join(dir, "run-1.log")
	if err := os.WriteFile(one, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	st, err := ParseFile(one)
	if err != nil {
		t.Fatal(err)
	}
	if st.Execs != 3000 {
		t.Errorf("executions: want 3000, got %d", st.Execs)
	}
	if st.NewUnits != 10 {
		t.Errorf("new units: want 10, got %d", st.NewUnits)
	}
	// 3000 runs over the LONGEST worker's 100 seconds, not over 200.
	if st.Rate != 30 {
		t.Errorf("rate: want 30, got %v", st.Rate)
	}

	// And the same file, read as a sweep with a banner, agrees.
	sweepBody := "fuzzing x_fuzzer for 600s\n" + body
	two := filepath.Join(dir, "sweep-round1.log")
	os.WriteFile(two, []byte(sweepBody), 0o644)
	per, err := ParseSweep(two)
	if err != nil {
		t.Fatal(err)
	}
	if per["x_fuzzer"].Rate != st.Rate || per["x_fuzzer"].Execs != st.Execs {
		t.Errorf("the two parsers disagree: sweep %+v vs single %d/%v",
			per["x_fuzzer"], st.Execs, st.Rate)
	}
}

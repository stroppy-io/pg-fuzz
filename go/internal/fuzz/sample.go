package fuzz

import (
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// THE MID-SLICE SAMPLE SERIES.
//
// A slice records what it REACHED and, since the trajectory work, a summary of
// whether it moved. Neither can see a stall, and the reason is in libFuzzer's
// own output: it prints densely while productive and nothing at all while
// stuck. A summary derived from that log inherits the same blindness -- a
// target that found nothing for twenty minutes and a target that finished
// early look alike in it.
//
// The shell sampled at a fixed cadence instead, so the gaps are visible: the
// rows keep arriving at 15-second intervals whether or not the fuzzer has
// anything to say, and "seconds since the frontier last advanced" and "RSS
// climbing toward an OOM" become computable. That series was not ported.
//
// CHEAP BY CONSTRUCTION. One cgroup read and a tail of the log. The corpus is
// deliberately NOT counted here: a find over 146,000 files every 15 seconds
// would cost more than the fuzzing it is watching.
//
// A MONITORING LOOP MUST NOT DIE OF THE THING IT MONITORS NOT HAVING HAPPENED
// YET. The shell's version did: it ran under `set -e`, its first grep found no
// progress line because libFuzzer had not printed one, and the sampler exited
// on iteration one leaving an empty file. Every read here tolerates absence.

// SampleInterval is how often a slice is sampled.
const SampleInterval = 15 * time.Second

// Sample is one observation of a running slice.
type Sample struct {
	T      int64   `json:"t"`
	DT     int     `json:"dt"`
	Target string  `json:"target"`
	CPUSec float64 `json:"cpu_s"`
	// Pointers, so a field libFuzzer has not printed yet is absent rather
	// than zero. Nought executions and "no line yet" are different facts, and
	// this file exists to make a stall visible.
	Execs *int `json:"execs"`
	Cov   *int `json:"cov"`
	Ft    *int `json:"ft"`
	Corp  *int `json:"corp"`
	RSSMB *int `json:"rss_mb"`
}

var reProgress = regexp.MustCompile(
	`#(\d+)\s.*?cov: (\d+) ft: (\d+)(?:.*?corp: (\d+))?(?:.*?rss: (\d+))?`)

// sampleLog reads the newest progress line out of a log's tail.
//
// The TAIL, not the file: these run to gigabytes, and the newest line is the
// only one this wants.
func sampleLog(path string, target string, start time.Time, cpu float64) Sample {
	s := Sample{
		T: time.Now().Unix(), DT: int(time.Since(start).Seconds()),
		Target: target, CPUSec: cpu,
	}
	f, err := os.Open(path)
	if err != nil {
		return s
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return s
	}
	const window = 20000
	off := fi.Size() - window
	if off < 0 {
		off = 0
	}
	buf := make([]byte, fi.Size()-off)
	if _, err := f.ReadAt(buf, off); err != nil && len(buf) == 0 {
		return s
	}
	// The LAST match in the window, which is the newest line.
	ms := reProgress.FindAllStringSubmatch(string(buf), -1)
	if len(ms) == 0 {
		return s
	}
	m := ms[len(ms)-1]
	set := func(dst **int, raw string) {
		if raw == "" {
			return
		}
		if n, err := strconv.Atoi(raw); err == nil {
			*dst = &n
		}
	}
	set(&s.Execs, m[1])
	set(&s.Cov, m[2])
	set(&s.Ft, m[3])
	set(&s.Corp, m[4])
	set(&s.RSSMB, m[5])
	return s
}

// containerCPUSec is a container's CPU time, from cgroup v2 or v1.
//
// Returns 0 when it cannot be read, which is not an error worth reporting: the
// sample is still worth writing without it, and a machine whose cgroup layout
// differs should not lose its whole sample series over one field.
func containerCPUSec(name string) float64 {
	id, err := exec.Command("docker", "inspect", "--format", "{{.Id}}", name).Output()
	if err != nil {
		return 0
	}
	cid := strings.TrimSpace(string(id))
	if cid == "" {
		return 0
	}
	for _, p := range []string{
		"/sys/fs/cgroup/system.slice/docker-" + cid + ".scope/cpu.stat",
		"/sys/fs/cgroup/docker/" + cid + "/cpu.stat",
	} {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(line, "usage_usec ") {
				if n, err := strconv.ParseFloat(strings.Fields(line)[1], 64); err == nil {
					return n / 1e6
				}
			}
		}
	}
	return 0
}

// SamplePath is where a slice's samples go: beside its log.
func SamplePath(logPath string) string {
	return strings.TrimSuffix(logPath, ".log") + ".samples.jsonl"
}

// AppendSample writes one row. Errors are swallowed deliberately: a slice must
// not fail because its monitoring could not be written.
func AppendSample(path string, s Sample) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, `{"t":%d,"dt":%d,"target":%q,"cpu_s":%.1f`,
		s.T, s.DT, s.Target, s.CPUSec)
	for _, kv := range []struct {
		k string
		v *int
	}{{"execs", s.Execs}, {"cov", s.Cov}, {"ft", s.Ft},
		{"corp", s.Corp}, {"rss_mb", s.RSSMB}} {
		if kv.v == nil {
			fmt.Fprintf(f, `,%q:null`, kv.k)
			continue
		}
		fmt.Fprintf(f, `,%q:%d`, kv.k, *kv.v)
	}
	fmt.Fprintln(f, "}")
}

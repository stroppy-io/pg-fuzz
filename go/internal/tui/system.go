package tui

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Disk, docker and load -- the three things that end a campaign early.
//
// Disk because a full filesystem stops the run; containers because a stopped
// campaign that left containers behind looks idle and is not; load because
// oversubscription silently corrupts timing-dependent results.

// SystemStats is the machine's state.
type SystemStats struct {
	FreeG, TotalG, UsedPct int
	Load                   float64
	Blocked                int
	CPUs                   int
	CPUPct                 *float64
	Containers, Ours       int
}

// cpuPrev holds the last /proc/stat reading, so utilisation is measured
// between calls rather than since boot.
var cpuPrev struct{ total, idle uint64 }

// CPUPercent is utilisation SINCE THE LAST CALL -- the number that reads
// without interpretation.
//
// Load average needs explaining every time: a campaign SHOULD sit above the
// core count, because each worker is surrounded by helper processes that are
// occasionally runnable. "30 of 24" looks like trouble and is not. "99%" says
// the machine is fully used; "60%" says it is being wasted.
func CPUPercent() *float64 {
	b, err := os.ReadFile("/proc/stat")
	if err != nil {
		return nil
	}
	line := strings.SplitN(string(b), "\n", 2)[0]
	fields := strings.Fields(line)
	if len(fields) < 6 {
		return nil
	}
	var vals []uint64
	for _, f := range fields[1:] {
		v, err := strconv.ParseUint(f, 10, 64)
		if err != nil {
			return nil
		}
		vals = append(vals, v)
	}
	var total uint64
	for _, v := range vals {
		total += v
	}
	idle := vals[3] + vals[4]

	prevTotal, prevIdle := cpuPrev.total, cpuPrev.idle
	cpuPrev.total, cpuPrev.idle = total, idle
	if prevTotal == 0 {
		// The first call has nothing to measure against, and reporting 0%
		// would say the machine is idle when it may be saturated.
		return nil
	}
	dt, di := total-prevTotal, idle-prevIdle
	if dt == 0 {
		return nil
	}
	p := 100 * float64(dt-di) / float64(dt)
	if p < 0 {
		p = 0
	}
	if p > 100 {
		p = 100
	}
	return &p
}

// ReadSystem gathers the machine's state.
func ReadSystem(path string) SystemStats {
	out := SystemStats{CPUs: runtime.NumCPU()}
	var st syscall.Statfs_t
	if syscall.Statfs(path, &st) == nil {
		out.FreeG = int(uint64(st.Bavail) * uint64(st.Bsize) >> 30)
		out.TotalG = int(st.Blocks * uint64(st.Bsize) >> 30)
		if out.TotalG > 0 {
			out.UsedPct = 100 - out.FreeG*100/out.TotalG
		}
	}
	if b, err := os.ReadFile("/proc/loadavg"); err == nil {
		if f := strings.Fields(string(b)); len(f) > 0 {
			out.Load, _ = strconv.ParseFloat(f[0], 64)
		}
	}
	// Load alone cannot tell saturation from thrashing. A campaign should sit
	// above the core count -- the supporting processes around each worker are
	// occasionally runnable -- and that is healthy as long as the CPU is
	// actually busy and nothing is stuck in uninterruptible I/O.
	out.Blocked = blockedProcs()
	// TWO READINGS, a moment apart, when there is no previous one.
	//
	// Utilisation is a difference between two samples of /proc/stat, so the
	// first call in a process has nothing to compare against. In the loop that
	// does not matter -- the next refresh has one. In the one-frame mode a
	// pipe gets, it meant the dashboard printed "cpu --" every single time,
	// which reads as "not measured" on a machine that is fully busy.
	out.CPUPct = CPUPercent()
	if out.CPUPct == nil {
		time.Sleep(120 * time.Millisecond)
		out.CPUPct = CPUPercent()
	}
	out.Containers, out.Ours = dockerCounts()
	return out
}

// blockedProcs counts processes in uninterruptible sleep, read from /proc
// rather than by shelling out to ps.
func blockedProcs() int {
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range ents {
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		b, err := os.ReadFile("/proc/" + e.Name() + "/stat")
		if err != nil {
			continue
		}
		// The state letter follows the parenthesised comm, which may itself
		// contain spaces or brackets -- so find the LAST ')'.
		i := strings.LastIndex(string(b), ")")
		if i < 0 || i+2 >= len(b) {
			continue
		}
		if b[i+2] == 'D' {
			n++
		}
	}
	return n
}

func dockerCounts() (total, ours int) {
	out, err := exec.Command("docker", "ps", "--no-trunc", "--format", "{{.Mounts}}").Output()
	if err != nil {
		return 0, 0
	}
	for _, l := range strings.Split(string(out), "\n") {
		if strings.TrimSpace(l) == "" {
			continue
		}
		total++
		if strings.Contains(l, "/pgfuzz") {
			ours++
		}
	}
	return total, ours
}

// StatusLine renders the machine's state, with the one warning that matters
// most first.
func StatusLine(s SystemStats) string {
	warn := ""
	switch {
	case s.FreeG < 20:
		warn = "  DISK LOW -- campaigns stop below 20G"
	case s.Blocked >= 4:
		warn = fmt.Sprintf("  %d procs blocked on I/O -- disk bound", s.Blocked)
	case s.Load > float64(s.CPUs)*2:
		warn = "  heavily oversubscribed"
	}
	cpu := "cpu --"
	if s.CPUPct != nil {
		cpu = fmt.Sprintf("cpu %.0f%% busy", *s.CPUPct)
	}
	return fmt.Sprintf("%s   %d vCPUs, %.0f runnable   docker %d ours / %d   disk %dG free%s",
		cpu, s.CPUs, s.Load, s.Ours, s.Containers, s.FreeG, warn)
}

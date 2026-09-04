package coverage

import (
	"encoding/json"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// A COVERAGE PASS HAS TO BE VISIBLE WHILE IT RUNS.
//
// The dashboard reads container names to say what is happening, and matches
// only `pgfuzz-run-`. A coverage pass runs through helper.py, whose containers
// carry no such name -- so for the whole of phase 3 the header said
// "idle -- no container running" while 23 replays were in flight. That is the
// same confident-wrong statement the docker-read fix addressed, on a path that
// fix did not touch.
//
// Container names cannot carry this: helper.py chooses them. So the coverage
// command writes what it is doing, and the dashboard reads the file. It also
// gives back the figure the Python had and the port lost -- how far through a
// BOUNDED pass it is, which a fuzzing round can never report.

// processAlive tests for a process without signalling it.
func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	return syscall.Kill(pid, 0) == nil
}

// LiveFile is where a coverage pass records itself, under the workspace.
const LiveFile = ".coverage-live.json"

// Live is a coverage pass in progress.
type Live struct {
	Workspace string `json:"ws"`
	Target    string `json:"target"`
	Done      int    `json:"done"`
	Total     int    `json:"total"`
	PID       int    `json:"pid"`
	Started   string `json:"started"`
}

// MarkLive records the target now being measured. Failing to write it must
// never stop a measurement: this is a display aid, not the work.
func MarkLive(wsDir string, l Live) {
	if l.PID == 0 {
		l.PID = os.Getpid()
	}
	if l.Started == "" {
		l.Started = time.Now().UTC().Format(time.RFC3339)
	}
	b, err := json.Marshal(l)
	if err != nil {
		return
	}
	_ = os.WriteFile(filepath.Join(wsDir, LiveFile), append(b, '\n'), 0o644)
}

// ClearLive removes the marker when the pass ends.
func ClearLive(wsDir string) { _ = os.Remove(filepath.Join(wsDir, LiveFile)) }

// ReadLive reports a coverage pass in progress, or nil.
//
// A MARKER OUTLIVES A KILL -9, so the process is checked rather than trusted:
// a stale file would leave the dashboard announcing a coverage pass that ended
// days ago, which is the same class of defect in the other direction.
func ReadLive(wsDir string) *Live {
	b, err := os.ReadFile(filepath.Join(wsDir, LiveFile))
	if err != nil {
		return nil
	}
	var l Live
	if json.Unmarshal(b, &l) != nil {
		return nil
	}
	if l.PID > 0 && !processAlive(l.PID) {
		return nil
	}
	return &l
}

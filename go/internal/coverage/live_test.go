package coverage

import (
	"os"
	"path/filepath"
	"testing"
)

// A COVERAGE PASS MUST NOT READ AS IDLE.
//
// The dashboard names what is running from container names and matches only
// `pgfuzz-run-`. helper.py picks its own names, so for the whole of phase 3
// the header said "idle -- no container running" while 23 replays were in
// flight. Container names cannot carry this; the pass records itself.
func TestLiveMarkerRoundTrips(t *testing.T) {
	ws := t.TempDir()
	if got := ReadLive(ws); got != nil {
		t.Fatalf("a workspace with no pass reported %+v", got)
	}

	MarkLive(ws, Live{Workspace: "w-cov", Target: "jsonb_fuzzer", Done: 4, Total: 23})
	got := ReadLive(ws)
	if got == nil {
		t.Fatal("the marker did not read back")
	}
	if got.Target != "jsonb_fuzzer" || got.Done != 4 || got.Total != 23 {
		t.Errorf("marker lost information: %+v", got)
	}
	if got.Started == "" || got.PID == 0 {
		t.Errorf("marker carries no time or pid: %+v", got)
	}

	ClearLive(ws)
	if got := ReadLive(ws); got != nil {
		t.Errorf("the marker survived the pass: %+v", got)
	}
}

// A MARKER OUTLIVES A KILL -9, so the process is checked rather than trusted.
// A stale file would leave the dashboard announcing a coverage pass that ended
// days ago -- the same confident-wrong statement in the other direction.
func TestLiveMarkerIgnoresADeadProcess(t *testing.T) {
	ws := t.TempDir()
	MarkLive(ws, Live{Workspace: "w", Target: "t", PID: 1 << 30})
	if got := ReadLive(ws); got != nil {
		t.Errorf("a marker from a dead process was believed: %+v", got)
	}
}

// A corrupt marker is not a coverage pass either.
func TestLiveMarkerIgnoresGarbage(t *testing.T) {
	ws := t.TempDir()
	if err := os.WriteFile(filepath.Join(ws, LiveFile), []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := ReadLive(ws); got != nil {
		t.Errorf("garbage parsed as a pass: %+v", got)
	}
}

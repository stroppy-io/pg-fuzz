package build

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// THE LOG HAS TO SURVIVE THE PROCESS.
//
// The shell kept <ws>/builds/<key>.log -- the whole helper.py output -- and a
// .buildtime.json it read back to estimate the next build. The port buffered
// the output in memory and re-printed only the lines matching
// error:|undefined reference|FAILED on failure, so "why did this build fail"
// was answerable only if somebody had been watching.
func TestBuildLogIsKept(t *testing.T) {
	dir := t.TempDir()
	r := Request{LogDir: filepath.Join(dir, "builds"), LogKey: "ref__address__libfuzzer"}

	p := writeBuildLog(r, []byte("configure: error: no acceptable C compiler\n"),
		92*time.Second, false)
	if p == "" {
		t.Fatal("no log written")
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) == "" {
		t.Error("the log is empty")
	}

	// The timing, in a form something can read back. Prose in a worklog does
	// not answer "how long does a cold build take here".
	tb, err := os.ReadFile(filepath.Join(r.LogDir, r.LogKey+".buildtime.json"))
	if err != nil {
		t.Fatal(err)
	}
	var bt struct {
		Seconds float64 `json:"seconds"`
		OK      bool    `json:"ok"`
	}
	if err := json.Unmarshal(tb, &bt); err != nil {
		t.Fatal(err)
	}
	if bt.Seconds != 92 {
		t.Errorf("seconds = %v, want 92", bt.Seconds)
	}
	if bt.OK {
		t.Error("a failed build was recorded as ok")
	}
}

// NO LOG DIRECTORY MEANS NO LOG, so the library stays usable from a test
// without writing into somebody's workspace.
func TestBuildLogOptOut(t *testing.T) {
	if p := writeBuildLog(Request{}, []byte("x"), time.Second, true); p != "" {
		t.Errorf("wrote %q with no LogDir", p)
	}
}

// A LOG THAT CANNOT BE WRITTEN MUST NOT FAIL THE BUILD. A successful build
// reported as failed because of its log is a worse outcome than a missing log.
func TestBuildLogFailureIsSilent(t *testing.T) {
	f := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if p := writeBuildLog(Request{LogDir: f, LogKey: "k"}, []byte("x"), time.Second, true); p != "" {
		t.Errorf("wrote %q into a path that is a file", p)
	}
}

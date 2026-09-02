package campaign

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A SLICE IS RECORDED WHEN IT FINISHES, not when the workspace does.
//
// The series is the model, and a model written only on the happy path is not
// one. Batching a whole workspace meant a campaign stopped mid-sweep -- by the
// deadline, by Ctrl-C, by a kill -9 -- lost every slice it had already
// completed. Caught in a smoke test: ten targets and five minutes of real
// fuzzing in, series.jsonl did not exist.
//
// This pins the property the fix restores: rows readable while the sweep is
// still running.
func TestSeriesIsReadableBeforeTheSweepEnds(t *testing.T) {
	dir := t.TempDir()
	s := Series{Path: filepath.Join(dir, "series.jsonl")}

	for i, target := range []string{"a_fuzzer", "b_fuzzer"} {
		if err := s.Append(Slice{
			RunID: "r", Round: 1, Workspace: "ws", Target: target,
			Execs: 100 * (i + 1), Alive: true,
		}); err != nil {
			t.Fatal(err)
		}
		// Read it back NOW, as a watcher or a killed campaign's successor
		// would -- not after the loop.
		got, err := s.Read()
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != i+1 {
			t.Fatalf("after %d slices, read %d rows", i+1, len(got))
		}
		if got[i].Target != target {
			t.Errorf("row %d attributed to %q, want %q", i, got[i].Target, target)
		}
	}

	// And the file is on disk, not buffered in the process.
	b, err := os.ReadFile(s.Path)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) == 0 {
		t.Error("series.jsonl is empty on disk")
	}
}

// The hard stop is sized from the workspaces actually in the campaign, not
// from a constant that happens to match this project's target count. A
// workspace with more targets was given a guard that fires mid-sweep; one
// with fewer got a guard three times longer than it needs.
func TestHardStopIsSizedFromTheWidestWorkspace(t *testing.T) {
	for _, tc := range []struct {
		name    string
		entries []Entry
		want    time.Duration
	}{
		{"one narrow workspace",
			[]Entry{{Targets: make([]string, 4)}}, 4 * 10 * 3 * time.Second},
		{"the widest of several",
			[]Entry{{Targets: make([]string, 4)}, {Targets: make([]string, 40)}},
			40 * 10 * 3 * time.Second},
		{"no entries at all still bounds something",
			nil, 1 * 10 * 3 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := Config{PerTarget: 10, Entries: tc.entries}
			if got := defaultOverrun(c); got != tc.want {
				t.Errorf("want %s, got %s", tc.want, got)
			}
		})
	}
}

package scenario

import (
	"os"
	"path/filepath"
	"testing"
)

// Every recorded scenario must parse, with no unknown fields.
//
// This is the first gate of the port and the cheapest: if the Go model cannot
// read what the Python generator wrote, nothing downstream is worth writing.
// DisallowUnknownFields makes a forgotten key a failure here rather than a
// silently missing step in a reproduction later.
func TestParsesEveryRecordedScenario(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("testdata", "*.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no fixtures: %v", err)
	}
	for _, f := range files {
		t.Run(filepath.Base(f), func(t *testing.T) {
			b, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			r, err := UnmarshalStrict(b)
			if err != nil {
				t.Fatalf("%v", err)
			}
			if r.Failure == "" {
				t.Error("no recorded failure: this fixture proves nothing")
			}
			if len(r.Scenario.Tables) == 0 {
				t.Error("no tables")
			}
			for _, s := range r.Scenario.Steps {
				if !KnownOp(s.Op) {
					t.Errorf("step %q is not in Ops -- the port cannot replay this finding", s.Op)
				}
			}
		})
	}
	t.Logf("%d recorded scenarios", len(files))
}

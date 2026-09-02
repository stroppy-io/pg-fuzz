package scenario

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Every operation the recorded scenarios use must be planned.
//
// An unplanned op means the scenario runs short, and a scenario that runs
// short is a different experiment with the same seed number -- it will
// silently stop reproducing and look like the defect went away.
func TestEveryOpIsPlanned(t *testing.T) {
	sc := Scenario{Tables: []Table{{Name: "t0", Rows: 500, AM: "orioledb"}}}
	for _, op := range Ops {
		p, ok := PlanStep(Step{Op: op, Table: "t0"}, sc)
		if !ok {
			t.Errorf("op %q has no plan", op)
			continue
		}
		switch p.Kind {
		case SQL, Concurrent:
			if len(p.SQL) == 0 {
				t.Errorf("op %q plans no statements", op)
			}
			for _, s := range p.SQL {
				if !strings.HasSuffix(strings.TrimSpace(s), ";") {
					t.Errorf("op %q: statement not terminated: %q", op, s)
				}
			}
		case Control:
			if p.Ctl == "" {
				t.Errorf("op %q is Control with no action", op)
			}
		}
	}
}

// And every op appearing in the corpus must be in Ops -- the two lists have to
// agree, or one of them is lying about what this port can replay.
func TestCorpusOpsAreDeclared(t *testing.T) {
	files, _ := filepath.Glob(filepath.Join("testdata", "*.json"))
	seen := map[string]bool{}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var r Record
		if err := json.Unmarshal(b, &r); err != nil {
			t.Fatal(err)
		}
		for _, s := range r.Scenario.Steps {
			seen[s.Op] = true
		}
	}
	for op := range seen {
		if !KnownOp(op) {
			t.Errorf("corpus uses %q, Ops does not declare it", op)
		}
	}
	for _, op := range Ops {
		if !seen[op] {
			t.Logf("declared but unused by the corpus: %s", op)
		}
	}
	t.Logf("%d distinct ops across %d scenarios", len(seen), len(files))
}

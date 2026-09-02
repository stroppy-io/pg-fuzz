package scenario

import "testing"

func TestGenerateIsDeterministic(t *testing.T) {
	// Two runs of one seed must build the same experiment, or a scenario that
	// fails cannot be re-run.
	a, b := Generate(42, true), Generate(42, true)
	if RenderSetup(a) != RenderSetup(b) {
		t.Error("the same seed produced two different scenarios")
	}
	if RenderSetup(Generate(42, true)) == RenderSetup(Generate(43, true)) {
		t.Error("two seeds produced the same scenario")
	}
}

// Every generated scenario must render and every step must be planned --
// otherwise the generator produces experiments the runner cannot carry out.
func TestGeneratedScenariosAreRunnable(t *testing.T) {
	for seed := 0; seed < 200; seed++ {
		s := Generate(seed, seed%2 == 0)
		if len(s.Tables) == 0 {
			t.Fatalf("seed %d has no tables", seed)
		}
		if RenderSetup(s) == "" {
			t.Fatalf("seed %d rendered nothing", seed)
		}
		for _, st := range s.Steps {
			if _, ok := PlanStep(st, s); !ok {
				t.Fatalf("seed %d: step %q has no plan", seed, st.Op)
			}
			// A step naming a table that cannot take it fails at the step
			// rather than at a defect, and a scenario that dies in setup
			// tests nothing.
			tbl := findTable(s, st.Table)
			if tbl == nil {
				t.Fatalf("seed %d: step %q names a table that does not exist", seed, st.Op)
			}
			switch st.Op {
			case "attach_partition", "detach_partition", "move_across_partition":
				if !tbl.Partitioned {
					t.Errorf("seed %d: %s on an unpartitioned table", seed, st.Op)
				}
			case "set_tablespace", "move_index":
				if tbl.Tablespace == nil {
					t.Errorf("seed %d: %s with no tablespace", seed, st.Op)
				}
			case "prepare_2pc":
				if tbl.AM == "orioledb" {
					t.Errorf("seed %d: prepare_2pc on orioledb, which rejects it outright", seed)
				}
			}
		}
	}
}

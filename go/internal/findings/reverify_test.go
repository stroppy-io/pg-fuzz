package findings

import (
	"os"
	"path/filepath"
	"testing"
)

func withFiles(t *testing.T, names ...string) string {
	t.Helper()
	d := t.TempDir()
	for _, n := range names {
		if err := os.WriteFile(filepath.Join(d, n), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return d
}

func anyWS(name string) string {
	if name == "" {
		return ""
	}
	return "/ws/" + name
}

// A finding with 28 artifacts still holds if ANY one of them reproduces.
// Taking only the first turns a finding that reproduces one time in
// twenty-eight into "no longer reproduces" -- and that verdict retires a real
// defect.
func TestPlanTakesEveryArtifactUpToTheCap(t *testing.T) {
	var names []string
	for i := 0; i < MaxArtifacts+8; i++ {
		names = append(names, "crash-"+string(rune('a'+i)))
	}
	dir := withFiles(t, names...)

	f := Finding{Name: "F1", FoundBy: "xlogreader_fuzzer on pg17-10-add"}
	p := PlanFor(f, dir, anyWS)

	if p.Vehicle != LibFuzzer {
		t.Fatalf("vehicle = %v, want libfuzzer", p.Vehicle)
	}
	if len(p.Artifacts) != MaxArtifacts {
		t.Errorf("planned %d artifacts, want the cap of %d", len(p.Artifacts), MaxArtifacts)
	}
	if p.Target != "xlogreader_fuzzer" {
		t.Errorf("target = %q", p.Target)
	}
	if p.Workspace != "/ws/pg17-10-add" {
		t.Errorf("workspace = %q", p.Workspace)
	}
}

// Three vehicles, because a finding a fuzz target cannot carry still has to be
// re-checkable: a .sql runs against a real postmaster, a seed*.json replays a
// storage scenario.
func TestPlanPicksTheVehicleFromWhatWasRecorded(t *testing.T) {
	sqlDir := withFiles(t, "repro.sql")
	if got := PlanFor(Finding{Name: "F", FoundBy: "manual on pg17-10-add"}, sqlDir, anyWS); got.Vehicle != SQL {
		t.Errorf("a recorded .sql planned as %v", got.Vehicle)
	}
	scDir := withFiles(t, "seed131.json")
	if got := PlanFor(Finding{Name: "F", FoundBy: "storage on pg17-10-add"}, scDir, anyWS); got.Vehicle != StorageScenario {
		t.Errorf("a recorded scenario planned as %v", got.Vehicle)
	}
}

// A SKIP IS NEVER A PASS. Every case that cannot be checked has to say so
// with a reason, or "we could not look" becomes indistinguishable from "it is
// fixed" -- which is how a finding gets quietly retired.
func TestEveryUncheckableCaseSkipsWithAReason(t *testing.T) {
	for _, c := range []struct {
		name string
		f    Finding
		dir  string
		ws   func(string) string
	}{
		{"no vehicle", Finding{Name: "F", FoundBy: "source analysis"}, withFiles(t), anyWS},
		{"no workspace", Finding{Name: "F", FoundBy: "xlogreader_fuzzer"}, withFiles(t, "crash-a"), anyWS},
		{"workspace gone", Finding{Name: "F", FoundBy: "xlogreader_fuzzer on pg17-10-add"},
			withFiles(t, "crash-a"), func(string) string { return "" }},
		{"no artifacts", Finding{Name: "F", FoundBy: "xlogreader_fuzzer on pg17-10-add"},
			withFiles(t), anyWS},
	} {
		p := PlanFor(c.f, c.dir, c.ws)
		if p.Skip == "" {
			t.Errorf("%s: planned as checkable, must skip with a reason (%+v)", c.name, p)
		}
	}
}

func TestTargetAndWorkspaceAreReadFromProse(t *testing.T) {
	f := Finding{FoundBy: "`spi_query_fuzzer` on **pg17-10-1c-und**, round 4."}
	if got := TargetOf(f); got != "spi_query_fuzzer" {
		t.Errorf("TargetOf = %q", got)
	}
	if got := WorkspaceOf(f); got != "pg17-10-1c-und" {
		t.Errorf("WorkspaceOf = %q", got)
	}
	// "source analysis" is deliberately distinct from a fuzzer.
	if got := TargetOf(Finding{FoundBy: "source analysis"}); got != "" {
		t.Errorf("TargetOf invented a target: %q", got)
	}
}

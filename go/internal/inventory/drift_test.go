package inventory

import "testing"

// EDITIONS OF ONE TREE MUST BE ONE TREE.
//
// A campaign's workspaces are the same source built three ways. When they are
// not, nothing failed: the coverage numbers sat beside the corpus numbers in
// one report describing two different programs. The documented case is a -cov
// build made from stock upstream orafce while the fuzzing builds used the
// patched tree.
func TestDriftCatchesADifferentTree(t *testing.T) {
	same := []Edition{
		{Workspace: "w-add", PGSHA: "abc", Patches: "p.patch",
			Plugins: map[string]string{"orafce": "111"}},
		{Workspace: "w-und", PGSHA: "abc", Patches: "p.patch",
			Plugins: map[string]string{"orafce": "111"}},
	}
	if d := DriftIn(same); len(d) != 0 {
		t.Errorf("identical editions reported drift: %v", d)
	}

	// The documented case: one edition built the plugin from a different tree.
	same[1].Plugins["orafce"] = "222"
	d := DriftIn(same)
	if len(d) != 1 || d[0].What != "plugin:orafce" {
		t.Fatalf("got %v, want the plugin difference", d)
	}
	if !contains(d[0].String(), "w-add") || !contains(d[0].String(), "w-und") {
		t.Errorf("the message does not name both sides: %s", d[0])
	}
}

func TestDriftCatchesCommitAndPatchDifferences(t *testing.T) {
	eds := []Edition{
		{Workspace: "a", PGSHA: "abc", Patches: "p.patch"},
		{Workspace: "b", PGSHA: "def", Patches: ""},
	}
	got := map[string]bool{}
	for _, d := range DriftIn(eds) {
		got[d.What] = true
	}
	if !got["pg_ref_sha"] || !got["patches"] {
		t.Errorf("missed a difference: %v", got)
	}
}

// ONLY WHAT IS PRESENT IS COMPARED. A workspace with no recorded commit has
// not been built, and calling that drift would fail every campaign with a
// workspace it has not reached yet.
func TestDriftIgnoresUnbuiltWorkspaces(t *testing.T) {
	eds := []Edition{
		{Workspace: "built", PGSHA: "abc", Patches: "p.patch"},
		{Workspace: "not-built"},
	}
	if d := DriftIn(eds); len(d) != 0 {
		t.Errorf("an unbuilt workspace was reported as drift: %v", d)
	}
}

// A plugin in one edition and absent from another is a different
// CONFIGURATION, which the patch comparison covers -- not a commit difference.
func TestDriftIgnoresAPluginOnlyOneEditionHas(t *testing.T) {
	eds := []Edition{
		{Workspace: "a", PGSHA: "abc", Plugins: map[string]string{"orafce": "1"}},
		{Workspace: "b", PGSHA: "abc"},
	}
	if d := DriftIn(eds); len(d) != 0 {
		t.Errorf("an absent plugin was reported as a commit difference: %v", d)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}

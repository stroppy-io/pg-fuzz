package tui

import "testing"

// THE ENGINE'S COMMIT WINS WHERE THERE IS ONE.
//
// For an OrioleDB workspace the PostgreSQL sha says which base the engine was
// built against, not which engine -- and the engine is what the run is
// testing. The Python preferred orioledb_sha in this column; the port only
// ever read the PostgreSQL one, so two workspaces on different engine commits
// showed the same value.
func TestCommitColumnPrefersTheEngine(t *testing.T) {
	got := commitFor("4639b6cfe3f310b71", "bdd9f464")
	if got != "bdd9f464" {
		t.Errorf("commit = %q, want the OrioleDB commit", got)
	}
	// A workspace with no engine commit keeps PostgreSQL's, shortened.
	if got := commitFor("4639b6cfe3f310b71", ""); got != "4639b6cfe3" {
		t.Errorf("commit = %q, want the shortened PostgreSQL commit", got)
	}
}

// PLACEHOLDERS MUST NOT DISPLACE A REAL COMMIT.
//
// An older driver wrote `orioledb_sha=(not built)` into nine workspaces. Since
// the display prefers that field, the placeholder took the column and rendered
// as "(not bui" -- so the guard has to run before the preference, not after.
func TestCommitColumnRejectsPlaceholders(t *testing.T) {
	for _, bad := range []string{"(not built)", "not built", "-", "unknown"} {
		if got := commitFor("4639b6cfe3f310b71", bad); got != "4639b6cfe3" {
			t.Errorf("orioledb_sha=%q gave %q; a placeholder took the column", bad, got)
		}
	}
	// Neither known: the column is empty rather than showing rubbish.
	if got := commitFor("", "(not built)"); got != "" {
		t.Errorf("commit = %q, want empty when nothing is known", got)
	}
}

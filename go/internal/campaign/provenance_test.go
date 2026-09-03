package campaign

import "testing"

// A REUSED BUILD MUST NOT CARRY THE PREVIOUS CAMPAIGN'S COMMIT.
//
// This is the defect the 2026-09-03 verification campaign exposed: the entry
// took its sha from workspace.conf, so a workspace built by an earlier
// campaign and reused by this one was sealed against the earlier commit. Both
// workspaces had compiled 4639b6cfe3; the manifest said 61636c17b3 for one of
// them, and nothing in the run could tell you which was true.
func TestProvenancePrefersTheBuildOverTheConf(t *testing.T) {
	e := ManifestEntry{Plugins: []string{"pgaudit", "pg_background"}}
	e.Provenance("4639b6cfe3", "61636c17b3", map[string]string{
		"pgaudit":       "538f89a",
		"pg_background": "5fc36a3",
	})

	if e.SHA != "4639b6cfe3" {
		t.Errorf("sha = %q, want the sha the build recorded, not the conf's", e.SHA)
	}
	want := []string{"pgaudit@538f89a", "pg_background@5fc36a3"}
	for i, w := range want {
		if e.Plugins[i] != w {
			t.Errorf("plugin %d = %q, want %q", i, e.Plugins[i], w)
		}
	}
}

// The conf is the fallback, not the source: a build old enough to predate
// BUILD-INFO.json is still better described by the conf than by nothing.
func TestProvenanceFallsBackToTheConf(t *testing.T) {
	e := ManifestEntry{Plugins: []string{"orafce"}}
	e.Provenance("", "61636c17b3", nil)

	if e.SHA != "61636c17b3" {
		t.Errorf("sha = %q, want the conf's when the build recorded none", e.SHA)
	}
	// A plugin with no recorded sha keeps its bare name rather than growing a
	// bare "@", which would read as a pin that is empty rather than absent.
	if e.Plugins[0] != "orafce" {
		t.Errorf("plugin = %q, want the bare name when no sha is known", e.Plugins[0])
	}
}

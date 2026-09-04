package tui

import "testing"

// A FILTERED GRID THAT DOES NOT SAY SO is indistinguishable from a campaign
// that lost workspaces, which is why Apply returns the total as well.
func TestApplyReportsTheTotal(t *testing.T) {
	rows := []Row{
		{Name: "gt-pg16", Built: true},
		{Name: "gt-pg17", Built: true, Running: "jsonb_fuzzer"},
		{Name: "vfy-pg17"},
	}
	shown, total := Apply(rows, FilterAll, "")
	if len(shown) != 3 || total != 3 {
		t.Errorf("all: %d of %d", len(shown), total)
	}

	shown, total = Apply(rows, FilterActive, "")
	if len(shown) != 2 || total != 3 {
		t.Errorf("active: %d of %d, want 2 of 3", len(shown), total)
	}
	shown, total = Apply(rows, FilterLive, "")
	if len(shown) != 1 || total != 3 {
		t.Errorf("live: %d of %d, want 1 of 3", len(shown), total)
	}
	// A coverage pass counts as live: it is work, and the whole point of the
	// live filter is finding what the machine is doing.
	rows[2].Covering = "geo_fuzzer"
	if shown, _ := Apply(rows, FilterLive, ""); len(shown) != 2 {
		t.Errorf("a workspace measuring coverage is not live: %d", len(shown))
	}
}

// A GLOB SPANS HYPHENS, because a workspace name is not a path and people
// expect gt-* to match gt-pg17.
func TestOnlyGlobSpansHyphens(t *testing.T) {
	rows := []Row{{Name: "gt-pg16"}, {Name: "gt-pg17"}, {Name: "vfy-pg17"}}
	shown, total := Apply(rows, FilterAll, "gt-*")
	if len(shown) != 2 || total != 3 {
		t.Errorf("got %d of %d, want 2 of 3", len(shown), total)
	}
	if shown, _ := Apply(rows, FilterAll, "*pg17"); len(shown) != 2 {
		t.Errorf("a trailing glob matched %d, want 2", len(shown))
	}
	if shown, _ := Apply(rows, FilterAll, "gt-pg17"); len(shown) != 1 {
		t.Errorf("an exact name matched %d, want 1", len(shown))
	}
}

// The cycle returns to all, so `f` is usable without a way back.
func TestFilterCycles(t *testing.T) {
	f := FilterAll
	seen := map[string]bool{}
	for i := 0; i < 3; i++ {
		seen[f.String()] = true
		f = f.Next()
	}
	if f != FilterAll {
		t.Error("the cycle does not return to all")
	}
	for _, want := range []string{"all", "active", "live"} {
		if !seen[want] {
			t.Errorf("%q is not in the cycle", want)
		}
	}
}

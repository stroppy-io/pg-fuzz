package triage

import (
	"reflect"
	"strings"
	"testing"
)

func TestWorkspacesNamedSkipsBareFamilies(t *testing.T) {
	txt := "Seen on `pg17-10-ext-all-add` and `pg17-10-ext-und`, not on pg17 generally."
	got := WorkspacesNamed(txt)
	want := []string{"pg17-10-ext-all-add", "pg17-10-ext-und"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// A GLOB SELECTS A CAMPAIGN, a family, or a sanitizer.
func TestInScopeMatchesAGlob(t *testing.T) {
	txt := "Reproduced on `pg17-10-ext-all-add`; not seen on `oriole17-add`."

	hit, ok := InScope(txt, []string{"pg17-10-ext-*"})
	if !ok || !reflect.DeepEqual(hit, []string{"pg17-10-ext-all-add"}) {
		t.Errorf("hit=%v ok=%v", hit, ok)
	}
	// The OrioleDB workspace is named in the same text and must not match.
	if _, ok := InScope(txt, []string{"pg17-10-ext-all-und"}); ok {
		t.Error("a workspace that is not named matched anyway")
	}
	// No pattern means no filtering, which is the existing behaviour.
	if _, ok := InScope(txt, nil); !ok {
		t.Error("an unfiltered call excluded a finding")
	}
}

// A write-up naming NO workspace is out of scope when a filter is given.
// Including it would put every unattributable finding into every campaign's
// report, which is the defect this filter exists to fix.
func TestInScopeExcludesTheUnattributable(t *testing.T) {
	if _, ok := InScope("A defect with no workspace named anywhere.",
		[]string{"pg17-10-ext-*"}); ok {
		t.Error("an unattributable write-up was claimed by a campaign")
	}
}

// A NOTE ABOUT AN EXCLUDED FINDING IS A NOTE ABOUT NOTHING.
//
// The header explaining why the count is what it is looped over a static
// override map, so a scoped document explained the re-attribution of a finding
// it had just filtered out -- in the one section whose job is accounting for
// the number.
func TestOverrideNotesOnlyForPresentFindings(t *testing.T) {
	var name string
	for n := range AttribOverride {
		name = n
		break
	}
	if name == "" {
		t.Skip("no attribution overrides to test with")
	}

	with := Render([]Finding{{Name: name, Area: "PostgreSQL core"}}, nil, nil, nil, nil)
	if !strings.Contains(with, name) {
		t.Errorf("the note is missing when the finding IS present")
	}

	without := Render([]Finding{{Name: "something-else", Area: "PostgreSQL core"}}, nil, nil, nil, nil)
	if strings.Contains(without, "`"+name+"` is counted under") {
		t.Errorf("the note explains %q, which this document excludes", name)
	}
}

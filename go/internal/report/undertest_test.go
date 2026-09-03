package report

import (
	"strings"
	"testing"

	"pgfuzz/internal/campaign"
)

// A REPORT MUST SAY WHAT IT TESTED.
//
// The page carried the numbers and none of the provenance: no commit, no
// patch series, no plugin pins. A vendor asked to fix something on the
// strength of it could not tell which tree it was found in. The manifest has
// recorded all of it since the campaign sealed it.
func TestReportShowsWhatWasUnderTest(t *testing.T) {
	var d Data
	d.WithManifest(campaign.Manifest{
		Sealed: true,
		Entries: []campaign.ManifestEntry{{
			Workspace: "vfy-pg17",
			Ref:       "origin/REL_17_STABLE",
			SHA:       "4639b6cfe3f310b71e1e227dd2a915b053992c9b",
			Sanitizer: "address",
			Plugins:   []string{"pgaudit@538f89a"},
			Patches:   []string{"0001-marker.patch@3db149b0069b1f14"},
			BuildOK:   true,
		}},
	})

	var b strings.Builder
	if err := Render(&b, d); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"What was tested",
		"4639b6cfe3f3",             // the commit, shortened to twelve
		"origin/REL_17_STABLE",     // and the ref it came from
		"0001-marker.patch@3db149", // which patch, and its hash
		"pgaudit@538f89a",          // which extension, at which commit
	} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("the page never mentions %q", want)
		}
	}
	// The full sha must not be printed where a twelve-character one is meant;
	// the table is read at a glance and a 40-character cell destroys it.
	if strings.Contains(b.String(), "4639b6cfe3f310b71e1e227dd2a915b053992c9b") {
		t.Error("the commit is printed in full inside the table")
	}
}

// An UNSEALED campaign says so, because its coverage cannot be re-measured
// from the slug: the corpus it ran against belongs to the workspace and has
// moved on since.
func TestUnsealedCampaignIsMarked(t *testing.T) {
	var d Data
	d.WithManifest(campaign.Manifest{
		Sealed:  false,
		Entries: []campaign.ManifestEntry{{Workspace: "w", BuildOK: true}},
	})
	var b strings.Builder
	if err := Render(&b, d); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "not\nsealed") &&
		!strings.Contains(b.String(), "not sealed") {
		t.Error("an unsealed campaign does not say so")
	}
}

// NO MANIFEST RENDERS NO SECTION, rather than an empty one that would read as
// "nothing patched, no plugins, unknown commit".
func TestNoManifestNoSection(t *testing.T) {
	var b strings.Builder
	if err := Render(&b, Data{Slug: "x"}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), "What was tested") {
		t.Error("the section rendered with nothing to show")
	}
}

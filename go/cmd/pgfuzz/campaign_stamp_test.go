package main

import (
	"strings"
	"testing"

	"pgfuzz/internal/findings"
)

// THE FIELD GOES BESIDE THE OTHER FIELDS.
//
// They are a block under the title and every reader of this format expects
// them there. A line appended to the end of a document is not a field, it is a
// postscript.
func TestInsertFieldJoinsTheFieldBlock(t *testing.T) {
	md := "# A defect\n\n" +
		"**Status:** open\n" +
		"**Found by:** `spi_query_fuzzer`\n\n" +
		"Some prose about it.\n"

	got, err := insertField(md, "Campaign", "pg17-10-ext-all")
	if err != nil {
		t.Fatal(err)
	}
	if findings.Campaign(got) != "pg17-10-ext-all" {
		t.Errorf("the field does not parse back: %q", got)
	}
	// Immediately after the last existing field, before the prose.
	lines := strings.Split(got, "\n")
	var iFound, iCamp, iProse int
	for i, l := range lines {
		switch {
		case strings.HasPrefix(l, "**Found by:**"):
			iFound = i
		case strings.HasPrefix(l, "**Campaign:**"):
			iCamp = i
		case strings.HasPrefix(l, "Some prose"):
			iProse = i
		}
	}
	if !(iFound < iCamp && iCamp < iProse) {
		t.Errorf("field placed at %d; fields end %d, prose starts %d:\n%s",
			iCamp, iFound, iProse, got)
	}
	// Nothing else may change.
	if !strings.Contains(got, "**Status:** open") ||
		!strings.Contains(got, "Some prose about it.") {
		t.Error("the rest of the write-up did not survive")
	}
}

// A write-up with no field block gets one after the title, rather than an
// error or a line dropped at the end.
func TestInsertFieldWithNoFieldBlock(t *testing.T) {
	got, err := insertField("# A defect\n\nJust prose.\n", "Campaign", "unknown")
	if err != nil {
		t.Fatal(err)
	}
	if findings.Campaign(got) != "unknown" {
		t.Errorf("the field does not parse back: %q", got)
	}
	if !strings.HasPrefix(got, "# A defect\n") {
		t.Errorf("the title moved:\n%s", got)
	}
}

// No title and no fields is a document this cannot place a field in, and it
// says so rather than guessing.
func TestInsertFieldRefusesWhenThereIsNowhere(t *testing.T) {
	if _, err := insertField("just some text\n", "Campaign", "unknown"); err == nil {
		t.Error("no error for a write-up with no title and no fields")
	}
}

// A FIELD WITHOUT A BLANK LINE IS NOT A FIELD.
//
// These write-ups separate their fields with a blank line. Written without
// one, Markdown folds the new line into the preceding paragraph -- the first
// run of this put a Campaign line inside the Cause text, changing how that
// field reads.
func TestInsertFieldMatchesTheSurroundingSpacing(t *testing.T) {
	md := "# A defect\n\n**Status:** open\n\n**Cause:** a long sentence.\n\nProse.\n"
	got, err := insertField(md, "Campaign", "unknown")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got, "a long sentence.\n**Campaign:**") {
		t.Errorf("the field was glued to the previous paragraph:\n%s", got)
	}
	if !strings.Contains(got, "a long sentence.\n\n**Campaign:** unknown") {
		t.Errorf("the field is not separated as its neighbours are:\n%s", got)
	}
}

// A write-up whose fields are NOT blank-separated keeps its own style.
func TestInsertFieldKeepsTightSpacingWhenThatIsTheStyle(t *testing.T) {
	md := "# A defect\n**Status:** open\n**Found by:** `t`\nProse.\n"
	got, err := insertField(md, "Campaign", "unknown")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "**Found by:** `t`\n**Campaign:** unknown") {
		t.Errorf("spacing was not preserved:\n%s", got)
	}
}

// A STATED CAMPAIGN IS DECISIVE; "unknown" is not.
//
// A write-up that names its campaign is answering the question, and a name
// that does not match is a definite no -- not a reason to go looking for a
// workspace in the prose that might. But "unknown" says the campaign is NOT
// ESTABLISHED, which is different from saying the finding belongs to no
// campaign, so the weaker prose evidence is still the best there is. Treating
// it as a definite no dropped a scoped report from ten findings to two.
func TestScopeOfPrefersTheFieldButFallsBackOnUnknown(t *testing.T) {
	known := map[string]bool{"pg17-10-ext-all-add": true}
	// The pattern is matched against a CAMPAIGN SLUG on the field path and
	// against WORKSPACE NAMES on the prose path. A workspace is conventionally
	// its campaign's slug plus a sanitizer suffix, so one glob covers both --
	// which is why -ws takes a glob rather than a name.
	pats := []string{"pg17-10-ext-all*"}

	stated := "# t\n\n**Campaign:** pg17-10-ext-all\n"
	if hit, ok := scopeOf(stated, pats, known); !ok || len(hit) != 1 {
		t.Errorf("a stated campaign did not match: %v %v", hit, ok)
	}

	other := "# t\n\n**Campaign:** some-other-run\n\nSeen on `pg17-10-ext-all-add`.\n"
	if _, ok := scopeOf(other, pats, known); ok {
		t.Error("a stated campaign that does not match was overridden by the prose")
	}

	unknown := "# t\n\n**Campaign:** unknown\n\nSeen on `pg17-10-ext-all-add`.\n"
	if _, ok := scopeOf(unknown, pats, known); !ok {
		t.Error("an unestablished campaign discarded the prose evidence it still has")
	}

	none := "# t\n\n**Campaign:** unknown\n\nNo workspace named.\n"
	if _, ok := scopeOf(none, pats, known); ok {
		t.Error("a finding with no evidence at all was claimed by a campaign")
	}
}

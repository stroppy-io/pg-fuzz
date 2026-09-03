package findings

import "testing"

// ONE PARSER FOR ONE FORMAT.
//
// This package and the final report each carried a regex for the same field,
// and they did not accept the same text. All 25 write-ups on disk use the form
// both happened to accept, so nothing was wrong -- and two documents that
// agree by coincidence are not documents you can rely on.
func TestFieldAcceptsBothColonPlacements(t *testing.T) {
	for _, md := range []string{
		"# t\n\n**Found by:** `spi_query_fuzzer`\n",
		"# t\n\n**Found by**: `spi_query_fuzzer`\n",
		"# t\n\n**Found by** `spi_query_fuzzer`\n",
	} {
		if got := Field(md, "Found by"); got != "`spi_query_fuzzer`" {
			t.Errorf("Field(%q) = %q", md, got)
		}
	}
}

// A FIELD IS A LINE, NOT A PHRASE.
//
// The report's regex was unanchored, so a write-up quoting another finding's
// "**Found by:**" inside an indented or quoted block matched it while this
// package's anchored one did not -- the two documents then attributed the same
// finding to different targets.
func TestFieldIsAnchoredToALine(t *testing.T) {
	quoted := "# t\n\nThe other write-up says    **Found by:** `regex_fuzzer`\n"
	if got := Field(quoted, "Found by"); got != "" {
		t.Errorf("Field matched mid-line text: %q", got)
	}
	// A blockquote is likewise not this write-up's own field.
	bq := "# t\n\n> **Found by:** `regex_fuzzer`\n"
	if got := Field(bq, "Found by"); got != "" {
		t.Errorf("Field matched a quoted line: %q", got)
	}
}

// The first occurrence wins, and bold inside the value is stripped, which is
// what readMeta has always done.
func TestFieldTakesTheFirstAndStripsBold(t *testing.T) {
	md := "# t\n\n**Status:** **open**\n\n**Status:** fixed\n"
	if got := Field(md, "Status"); got != "open" {
		t.Errorf("Field = %q, want the first, unbolded", got)
	}
	if got := Field(md, "Cause"); got != "" {
		t.Errorf("a missing field returned %q", got)
	}
}

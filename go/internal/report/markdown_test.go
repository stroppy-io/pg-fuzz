package report

import (
	"strings"
	"testing"

	"pgfuzz/internal/campaign"
	"pgfuzz/internal/findings"
)

func sample() Data {
	var d Data
	d.WithManifest(campaign.Manifest{
		Sealed: true,
		Entries: []campaign.ManifestEntry{{
			Workspace: "vfy-pg17", Ref: "origin/REL_17_STABLE",
			SHA:       "4639b6cfe3f310b71e1e227dd2a915b053992c9b",
			Sanitizer: "address",
			Plugins:   []string{"pgaudit@538f89a"},
			Patches:   []string{"0001-marker.patch@3db149b0"},
			BuildOK:   true,
		}},
	})
	d.Slug, d.Execs, d.Artifacts, d.Slices = "verify", 218556623, 9, 95
	d.Findings = []findings.Finding{{
		Name: "a-null-deref", Title: "to_nlower() dereferences NULL",
		Area: "third-party extensions", Status: "open", FoundBy: "`spi_query_fuzzer`",
		Cause: "no NULL check", Artifacts: 3,
	}}
	d.ByArea = []AreaRow{{Area: "third-party extensions", Count: 1}}
	d.ByTarget = []TargetRow{{Target: "spi_query_fuzzer", Count: 1}}
	return d
}

// THE MARKDOWN AND THE PAGE MUST DESCRIBE ONE RUN.
//
// Both render the same Data from one Gather. A second document assembled from
// a second reading of the record is how two reports of one campaign come to
// disagree -- which has happened in this repository three times.
func TestMarkdownCarriesWhatThePageCarries(t *testing.T) {
	d := sample()
	var md, html strings.Builder
	if err := RenderMarkdown(&md, d); err != nil {
		t.Fatal(err)
	}
	if err := Render(&html, d); err != nil {
		t.Fatal(err)
	}

	for _, want := range []string{
		"4639b6cfe3f3",               // the commit that was compiled
		"origin/REL_17_STABLE",       // and the ref it came from
		"0001-marker.patch@3db149b0", // which patch
		"pgaudit@538f89a",            // which extension, pinned
		"218,556,623",                // the executions, grouped
		"spi_query_fuzzer",
	} {
		if !strings.Contains(md.String(), want) {
			t.Errorf("the markdown never mentions %q", want)
		}
		if !strings.Contains(html.String(), want) {
			t.Errorf("the page never mentions %q -- the two have diverged", want)
		}
	}

	// WHERE THEY DIFFER, ON PURPOSE. The page summarises the findings by area
	// and by target; the Markdown also lists each one, because it is the
	// format read on a phone and pasted into an issue, where the write-up
	// itself is not one click away.
	if !strings.Contains(md.String(), "to_nlower() dereferences NULL") {
		t.Error("the markdown does not list the findings themselves")
	}
	if !strings.Contains(md.String(), "no NULL check") {
		t.Error("the markdown drops the cause")
	}

	// The finding count must agree between them, or one of the two is lying.
	if !strings.Contains(md.String(), "**1 distinct findings, triaged.**") {
		t.Error("the markdown does not state the finding count")
	}
	// And the artifact/finding distinction survives the format change.
	if !strings.Contains(md.String(), "An artifact is not a finding") {
		t.Error("the markdown dropped the artifact-versus-finding warning")
	}
	if !strings.Contains(md.String(), "standing findings") {
		t.Error("the markdown attributes the standing findings to this run")
	}
}

// An unsealed campaign says so in both formats: its coverage cannot be
// re-measured from the slug.
func TestMarkdownMarksUnsealed(t *testing.T) {
	d := sample()
	d.Sealed = false
	var b strings.Builder
	if err := RenderMarkdown(&b, d); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "not sealed") {
		t.Error("an unsealed campaign does not say so")
	}
}

// No manifest renders no provenance table rather than an empty one, which
// would read as "nothing patched, unknown commit".
func TestMarkdownOmitsAbsentProvenance(t *testing.T) {
	var b strings.Builder
	if err := RenderMarkdown(&b, Data{Slug: "x"}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), "What was tested") {
		t.Error("the section rendered with nothing to show")
	}
}

package report

import (
	"bytes"
	"html"
	"os"
	"regexp"
	"strings"
	"testing"
)

// THE GOLDENS IN testdata WERE PRODUCED BY THE PYTHON THIS PACKAGE REPLACED.
//
// index.cells.golden and index.prose.golden are the output of
// scripts/campaign-index.py, run against testdata/campaign, captured before
// that script was deleted. The test therefore proves EQUIVALENCE rather than
// self-consistency: a golden regenerated from this package would only prove
// that it still agrees with itself.
//
// They compare the semantic content -- every table cell, and every paragraph
// with source wrapping normalised away -- not the bytes. A restyle must be
// free; a changed number must not be.
//
// The one intentional difference is the footer, which the Python ended with
// the absolute path of the campaign directory. That leaks a local filesystem
// layout into a page meant to be shared, so it is dropped from the golden and
// from the Go page.

var (
	styleRe = regexp.MustCompile(`(?s)<style.*?</style>`)
	tableRe = regexp.MustCompile(`(?s)<table.*?</table>`)
	rowRe   = regexp.MustCompile(`(?s)<tr>(.*?)</tr>`)
	cellRe  = regexp.MustCompile(`(?s)<t[hd][^>]*>(.*?)</t[hd]>`)
	blockRe = regexp.MustCompile(`</?(p|h1|h2|h3|div|section|header|footer|title)[^>]*>`)
	tagRe   = regexp.MustCompile(`<[^>]*>`)
	wsRe    = regexp.MustCompile(`\s+`)
)

func flat(s string) string { return strings.TrimSpace(wsRe.ReplaceAllString(s, " ")) }

// cells renders every table as "cell | cell | cell", one row per line.
func cells(page string) string {
	var b strings.Builder
	for _, t := range tableRe.FindAllString(page, -1) {
		for _, r := range rowRe.FindAllStringSubmatch(t, -1) {
			var cs []string
			for _, c := range cellRe.FindAllStringSubmatch(r[1], -1) {
				cs = append(cs, flat(tagRe.ReplaceAllString(c[1], "")))
			}
			b.WriteString(strings.Join(cs, " | ") + "\n")
		}
		b.WriteString("--\n")
	}
	return b.String()
}

// prose returns the text outside tables, one line per block, with the source's
// own line wrapping removed -- where a template happens to break a line is not
// content.
func prose(page string) string {
	s := styleRe.ReplaceAllString(page, "")
	s = tableRe.ReplaceAllString(s, "")
	s = strings.ReplaceAll(s, "\n", " ")
	s = blockRe.ReplaceAllString(s, "\n")
	s = tagRe.ReplaceAllString(s, "")
	var out []string
	for _, l := range strings.Split(html.UnescapeString(s), "\n") {
		if l = flat(l); l != "" && !strings.HasPrefix(l, "Generated from") {
			out = append(out, l)
		}
	}
	return strings.Join(out, "\n") + "\n"
}

func TestIndexMatchesThePythonItReplaced(t *testing.T) {
	d, err := GatherIndex("testdata/campaign", "pg17-ext-all")
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := RenderIndex(&buf, d); err != nil {
		t.Fatal(err)
	}
	page := buf.String()

	for _, tc := range []struct {
		name, golden string
		got          string
	}{
		{"cells", "testdata/index.cells.golden", cells(page)},
		{"prose", "testdata/index.prose.golden", prose(page)},
	} {
		want, err := os.ReadFile(tc.golden)
		if err != nil {
			t.Fatal(err)
		}
		if got := tc.got; got != string(want) {
			t.Errorf("%s differ from the Python's output.\n--- want\n%s\n--- got\n%s",
				tc.name, want, got)
		}
	}
}

// The three runs in testdata carry the distinction the page exists to make:
// the fingerprint DEFINITION widened between them, which is not the same as
// the experiment changing.
func TestIndexSeparatesRedefinitionFromChange(t *testing.T) {
	d, err := GatherIndex("testdata/campaign", "pg17-ext-all")
	if err != nil {
		t.Fatal(err)
	}
	if !d.FPRedefined {
		t.Error("the fingerprint definition changed in this history and the page does not say so")
	}
	if d.FPChanged {
		t.Error("no run changed the experiment; the page claims one did")
	}
	for _, r := range d.Runs {
		if r.Changed {
			t.Errorf("%s marked as an experiment change; only the definition moved", r.Name)
		}
	}
}

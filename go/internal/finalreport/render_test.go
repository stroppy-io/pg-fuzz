package finalreport

import (
	"bytes"
	"encoding/json"
	"os"
	"pgfuzz/internal/report"
	"regexp"
	"testing"
)

// THE GOLDEN IS THE DOCUMENT THE PREVIOUS RENDERER PRODUCED.
//
// testdata/report.golden.html is the campaign report as it was published, and
// testdata/data.json is the exact gather it was rendered from. This test
// proves equivalence rather than self-consistency: a golden regenerated from
// this package would only prove that it still agrees with itself.
//
// It is a BYTE comparison of everything the DATA produces: every table, every
// figure, every number. That is where the defects were -- a dropped field, a
// float rendered without its decimal point, a table whose rows came out in a
// different order on every run -- and "close enough" is not a standard that can
// be checked on a document handed to people outside the project.
//
// THE PROSE IS NOT COMPARED, and that is a deliberate narrowing made on
// 2026-09-03. The published document says "What it turned up" over a count of
// the project's entire findings directory, which is a claim this report should
// never have made: it names one campaign and prints every finding, including
// eight from a storage engine that campaign did not build. Pinning the renderer
// to that document's narrative meant every correction to a wrong sentence
// failed a test that had nothing to say about the numbers.
//
// So the equivalence this proves is now: the Go renderer reproduces the
// Python's DATA rendering exactly. It no longer proves the surrounding words
// are identical, because some of them were wrong.
func TestReportMatchesThePublishedDocument(t *testing.T) {
	raw, err := os.ReadFile("testdata/data.json")
	if err != nil {
		t.Fatal(err)
	}
	var d Data
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatal(err)
	}
	var base struct {
		Tolerance  float64                       `json:"tolerance"`
		Floors     map[string]map[string]int     `json:"floors"`
		RateFloors map[string]map[string]float64 `json:"rate_floors"`
	}
	bb, err := os.ReadFile("testdata/baseline.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(bb, &base); err != nil {
		t.Fatal(err)
	}

	var got bytes.Buffer
	err = Render(&got, RenderInputs{
		Data:       d,
		Union:      ReadUnion("testdata/coverage-union.jsonl"),
		Floors:     base.Floors,
		RateFloors: base.RateFloors,
		Tolerance:  base.Tolerance,
		StoppedAt:  "2026-08-27 08:00:10",
	}, report.BaseCSS())
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile("testdata/report.golden.html")
	if err != nil {
		t.Fatal(err)
	}
	// The stylesheet is excluded too: the design system is allowed to evolve
	// and says nothing about the report's content. It is checked for BEING the
	// shared sheet rather than for its bytes.
	_, gotStyle := splitStyle(got.Bytes())
	if !bytes.Contains(gotStyle, []byte("--paper")) {
		t.Error("the report inlined no palette at all")
	}
	if !bytes.Equal(gotStyle, []byte(report.BaseCSS())) {
		t.Error("the report no longer inlines the shared stylesheet")
	}

	gotData, wantData := dataBearing(got.Bytes()), dataBearing(want)
	if len(wantData) == 0 {
		t.Fatal("no data-bearing elements found in the golden; the extractor moved")
	}
	if !bytes.Equal(gotData, wantData) {
		t.Errorf("the rendered data differs from the published document (%d bytes vs %d)",
			len(gotData), len(wantData))
		// Report the first differing line rather than the whole document.
		g, w := bytes.Split(gotData, []byte("\n")), bytes.Split(wantData, []byte("\n"))
		for i := 0; i < len(g) && i < len(w); i++ {
			if !bytes.Equal(g[i], w[i]) {
				t.Errorf("first difference at line %d:\n  want %s\n  got  %s", i+1, w[i], g[i])
				break
			}
		}
	}
}

// reDataBearing matches the elements a report's DATA produces: its tables and
// its headline figures. Everything else on the page is prose.
var reDataBearing = regexp.MustCompile(`(?s)<table.*?</table>|<div class="fig">.*?</div>`)

// dataBearing is every table and figure in a document, joined.
//
// This is what the golden compares. A dropped field, a mis-rendered float and a
// row-ordering change all land here; a corrected sentence does not.
func dataBearing(doc []byte) []byte {
	m := reDataBearing.FindAll(doc, -1)
	if m == nil {
		return nil
	}
	return bytes.Join(m, []byte("\n"))
}

// splitStyle separates a document's first <style> block from the rest.
func splitStyle(doc []byte) (body, style []byte) {
	i := bytes.Index(doc, []byte("<style>"))
	if i < 0 {
		return doc, nil
	}
	j := bytes.Index(doc[i:], []byte("</style>"))
	if j < 0 {
		return doc, nil
	}
	j += i + len("</style>")
	body = append(append([]byte{}, doc[:i]...), doc[j:]...)
	return body, doc[i:j]
}

// Go's map iteration is randomised, and this document ranks several tables by
// a value that ties. A report that shuffles its own rows between runs cannot
// be diffed against its predecessor, which is the whole point of publishing it.
func TestRenderIsDeterministic(t *testing.T) {
	raw, _ := os.ReadFile("testdata/data.json")
	var d Data
	json.Unmarshal(raw, &d)
	var first []byte
	for i := 0; i < 5; i++ {
		var b bytes.Buffer
		if err := Render(&b, RenderInputs{Data: d}, ""); err != nil {
			t.Fatal(err)
		}
		if first == nil {
			first = b.Bytes()
			continue
		}
		if !bytes.Equal(first, b.Bytes()) {
			t.Fatalf("render %d differs from the first", i+1)
		}
	}
}

package finalreport

import (
	"bytes"
	"encoding/json"
	"os"
	"pgfuzz/internal/report"
	"testing"
)

// THE GOLDEN IS THE DOCUMENT THE PREVIOUS RENDERER PRODUCED.
//
// testdata/report.golden.html is the campaign report as it was published, and
// testdata/data.json is the exact gather it was rendered from. This test
// proves equivalence rather than self-consistency: a golden regenerated from
// this package would only prove that it still agrees with itself.
//
// It is a BYTE comparison, deliberately. This document is an artifact handed
// to people outside the project; "close enough" is not a standard that can be
// checked, and every difference so far has been a real defect -- a dropped
// field, a float rendered without its decimal point, a table whose rows came
// out in a different order on every run.
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
	// THE STYLESHEET IS EXCLUDED, and only the stylesheet.
	//
	// The comparison is against a document published before this renderer
	// existed, so its <style> block is frozen at whatever the design system
	// was that day. Every legitimate fix to the shared stylesheet -- an
	// unstyled class, a palette split -- then fails this test while changing
	// nothing about the report's content, and the pressure is to stop fixing
	// the stylesheet rather than to update a golden that is only meaningful
	// because it was NOT regenerated here.
	//
	// So the body is still compared byte for byte, which is where every
	// difference this test has ever caught lived: a dropped field, a float
	// without its decimal point, a table whose rows came out in a different
	// order. The style block is checked separately, for being the shared
	// sheet rather than for its contents.
	gotBody, gotStyle := splitStyle(got.Bytes())
	wantBody, _ := splitStyle(want)

	if !bytes.Contains(gotStyle, []byte("--paper")) {
		t.Error("the report inlined no palette at all")
	}
	if !bytes.Equal(gotStyle, []byte(report.BaseCSS())) {
		t.Error("the report no longer inlines the shared stylesheet")
	}

	if !bytes.Equal(gotBody, wantBody) {
		t.Errorf("rendered report differs from the published one (%d bytes vs %d, styles aside)",
			len(gotBody), len(wantBody))
		// Report the first differing line rather than the whole document.
		g, w := bytes.Split(gotBody, []byte("\n")), bytes.Split(wantBody, []byte("\n"))
		for i := 0; i < len(g) && i < len(w); i++ {
			if !bytes.Equal(g[i], w[i]) {
				t.Errorf("first difference at line %d:\n  want %s\n  got  %s", i+1, w[i], g[i])
				break
			}
		}
	}
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

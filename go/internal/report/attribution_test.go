package report

import (
	"strings"
	"testing"

	"pgfuzz/internal/findings"
)

// A SLUG REPORT MUST NOT CLAIM THE PROJECT'S FINDINGS AS ITS OWN.
//
// Gather reads the project-wide FINDINGS directory, unfiltered, because a
// write-up records no campaign -- so every slug's report showed every write-up
// under "What it turned up", directly beneath that run's own elapsed time. The
// 23-minute verification campaign of 2026-09-03 rendered "0h23m elapsed" above
// "25 distinct findings", of which it had produced none.
//
// The data cannot be filtered, so the page stops claiming. The heading names
// the standing corpus and the note says the run's own result is the artifact
// count.
func TestFindingsAreNotAttributedToTheRun(t *testing.T) {
	var b strings.Builder
	err := Render(&b, Data{
		Slug:     "verify",
		Findings: []findings.Finding{{Name: "a", Title: "t", Area: "core"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := b.String()
	if strings.Contains(got, "What it turned up") {
		t.Error("the heading still attributes the standing findings to this run")
	}
	if !strings.Contains(got, "Findings on record") {
		t.Error("the findings section lost its heading")
	}
	if !strings.Contains(got, "standing findings") {
		t.Error("nothing tells the reader these are not this run's findings")
	}
}

package report

import (
	"strings"
	"testing"
)

// MASKING MUST BE VISIBLE BEFORE IT BECOMES A HABIT.
//
// The whole "what the gates let through" section was gated on .Streaks -- on a
// target having been masked in two CONSECUTIVE runs. The per-run table inside
// it depends on no such thing. So a run that masked targets, in a history
// where no target had yet been masked twice running, rendered as a history
// with no masking in it at all.
//
// That is the wrong way round: newly-started masking is the kind you can still
// do something about, and it was the only kind hidden.
func TestMaskingShowsBeforeItStreaks(t *testing.T) {
	d := IndexData{
		Runs: []RunRow{
			{Name: "r1", Label: "r1", Masked: 3, SkippedTargets: 3},
			{Name: "r2", Label: "r2"},
		},
	}
	// No streaks: nothing was masked twice in a row.
	var b strings.Builder
	if err := RenderIndex(&b, d); err != nil {
		t.Fatal(err)
	}
	got := b.String()
	if !strings.Contains(got, "What the gates let through") {
		t.Fatal("a run that masked targets rendered no masking section")
	}
	if !strings.Contains(got, "no streak to report") {
		t.Error("nothing explains why the streak table is absent")
	}
	if strings.Contains(got, "Masked without a break") {
		t.Error("the streak table rendered with no streaks")
	}
}

// Nothing masked anywhere still renders no section: an empty table would
// invite the reader to conclude the gates are weaker than they are.
func TestNoMaskingNoSection(t *testing.T) {
	var b strings.Builder
	if err := RenderIndex(&b, IndexData{Runs: []RunRow{{Name: "r1", Label: "r1"}}}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), "What the gates let through") {
		t.Error("the masking section rendered with nothing masked")
	}
}

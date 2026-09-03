package scenario

import "strings"

// The driver itself lives in internal/incontainer: it runs inside the builder
// image, as this same binary, against a postmaster it started. Nothing about a
// scenario is rendered into a script for a shell to interpret.
//
// What stays here is the wire between the two halves. The in-container driver
// prints one machine-readable line, and the host reads it back.

// ResultLine extracts the driver's verdict from a run's output.
func ResultLine(out string) string {
	for _, l := range strings.Split(out, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(l), "SFZ-RESULT: "); ok {
			return v
		}
	}
	return ""
}

// NoteLines extracts what the run recorded as having happened but not failed.
//
// A NOTE IS A PERTURBATION THAT DID NOT HAPPEN, or one that happened and was
// expected: a step the engine refused, a deadlock under contention, a writer
// that lost a race. Record.Notes existed from the start and nothing ever wrote
// it, so a scenario that skipped half its steps was indistinguishable from one
// that ran them -- and a reproducer's value depends entirely on which of those
// it was.
func NoteLines(out string) []string {
	var notes []string
	for _, l := range strings.Split(out, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(l), "SFZ-NOTE: "); ok {
			notes = append(notes, v)
		}
	}
	return notes
}

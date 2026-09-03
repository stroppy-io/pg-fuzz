package scenario

import "testing"

// Under concurrency a serialization failure or a deadlock is the engine doing
// its job. Reporting one as a finding manufactures defects, which is worse
// than missing them: it teaches the reader that this engine cries wolf. The
// port had no notion of these at all, so a concurrent step either ignored
// every error or would have failed on the expected ones.
func TestTransientAndUnsupportedAreNotFindings(t *testing.T) {
	for _, m := range []string{
		"ERROR:  could not serialize access due to concurrent update",
		"ERROR:  deadlock detected",
		"ERROR:  canceling statement due to lock timeout",
		"ERROR:  tuple concurrently updated",
	} {
		if !Transient(m) {
			t.Errorf("not recognised as transient: %s", m)
		}
	}
	for _, m := range []string{
		"ERROR:  VACUUM FULL is not supported on orioledb tables",
		"ERROR:  hash index does not support this",
	} {
		if !Unsupported(m) {
			t.Errorf("not recognised as a refusal: %s", m)
		}
	}
	// The ones that must still fail a scenario.
	for _, m := range []string{
		"TRAP: failed Assert(\"MyProc != NULL\")",
		"ERROR:  could not read block 42 in file base/1/2: read only 0 of 8192 bytes",
		"server closed the connection unexpectedly",
	} {
		if Transient(m) || Unsupported(m) {
			t.Errorf("a real failure was classified away: %s", m)
		}
	}
}

// A note is a perturbation that did not happen, or one that happened and was
// expected. Record.Notes existed from the start and nothing ever wrote it, so
// a scenario that skipped half its steps was indistinguishable from one that
// ran them.
func TestNoteLinesAreLiftedFromTheDriverStream(t *testing.T) {
	out := "SFZ-PHASE: setup\n" +
		"SFZ-NOTE: unsupported during vacuum_full: is not supported\n" +
		"SFZ-STEP: concurrent_write:t\n" +
		"SFZ-NOTE: transient during concurrent_write: deadlock detected\n" +
		"SFZ-RESULT: ok\n"
	notes := NoteLines(out)
	if len(notes) != 2 {
		t.Fatalf("got %d notes, want 2: %v", len(notes), notes)
	}
	if ResultLine(out) != "ok" {
		t.Errorf("the verdict was disturbed by the notes: %q", ResultLine(out))
	}
}

package census

import "testing"

// THE SANITIZER IS RECORDED, NOT SPELLED IN THE NAME.
//
// Sanitizer read the workspace name for a -add / -und suffix. On this host 34
// of 67 workspaces follow that convention and all 67 record sanitizer= in
// their config -- so every gt-* workspace, built with AddressSanitizer,
// classified as "other", and the summary's asan and ubsan columns undercounted
// by roughly half.
func TestSanitizerPrefersTheRecordedValue(t *testing.T) {
	known := map[string]string{
		"gt-pg17":  "address",
		"gt-pg18":  "undefined",
		"gt-p-cov": "coverage",
	}
	for ws, want := range map[string]string{
		"gt-pg17":  "asan",
		"gt-pg18":  "ubsan",
		"gt-p-cov": "coverage",
	} {
		if got := Sanitizer(ws, known); got != want {
			t.Errorf("Sanitizer(%q) = %q, want %q", ws, got, want)
		}
	}
	// The old name-suffix reading answered "other" for exactly these.
	if got := Sanitizer("gt-pg17", nil); got != "other" {
		t.Errorf("without a config, gt-pg17 = %q; the suffix cannot know", got)
	}
}

// The suffix survives as the fallback, which is the only case it was right
// about: a workspace whose config cannot be read.
func TestSanitizerFallsBackToTheSuffix(t *testing.T) {
	for ws, want := range map[string]string{
		"pg17-add": "asan",
		"pg17-und": "ubsan",
		"pg17":     "other",
	} {
		if got := Sanitizer(ws, nil); got != want {
			t.Errorf("Sanitizer(%q, nil) = %q, want %q", ws, got, want)
		}
	}
	// A recorded value always beats the suffix, even a contradictory one:
	// the config describes the build, the name describes a habit.
	if got := Sanitizer("pg17-add", map[string]string{"pg17-add": "undefined"}); got != "ubsan" {
		t.Errorf("got %q; the config must win over the name", got)
	}
}

// THE JSON MUST CARRY WHAT THE TABLE SHOWS. The summary computed the split on
// the way past and the schema did not record it, so every consumer had to
// reimplement the classification -- and any that read the name got the wrong
// answer.
func TestAnnotateFillsTheSchema(t *testing.T) {
	rows := []Row{{
		Signature:  "x",
		Workspaces: []string{"gt-pg17", "gt-pg18", "gt-pg19", "pg17-und"},
	}}
	Annotate(rows, map[string]string{
		"gt-pg17": "address", "gt-pg18": "address", "gt-pg19": "undefined",
	})
	if rows[0].ASan != 2 {
		t.Errorf("ASan = %d, want 2", rows[0].ASan)
	}
	if rows[0].UBSan != 2 { // gt-pg19 by config, pg17-und by suffix
		t.Errorf("UBSan = %d, want 2", rows[0].UBSan)
	}
	// Re-annotating must not accumulate.
	Annotate(rows, map[string]string{"gt-pg17": "address"})
	if rows[0].ASan != 1 {
		t.Errorf("ASan = %d after re-annotation, want 1", rows[0].ASan)
	}
}

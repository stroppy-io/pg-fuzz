package build

import (
	"os"
	"path/filepath"
	"testing"
)

func writeCheck(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "check.log")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// RAN IS SEPARATE FROM PASSED.
//
// A configure or make failure leaves no check.log at all, and reporting that
// as "0 failures" would turn a tree that cannot even build into a passing one
// -- the distinction every gate in this project turns on.
func TestParseCheckSeparatesRanFromPassed(t *testing.T) {
	if _, _, _, ran := parseCheck(filepath.Join(t.TempDir(), "nope")); ran {
		t.Error("a missing check.log reported that the suite ran")
	}
	// Present but truncated -- the build died part-way through the suite.
	if _, _, _, ran := parseCheck(writeCheck(t, "ok 1  - tablespace\n")); ran {
		t.Error("a log with no summary reported that the suite ran")
	}
}

func TestParseCheckAllPassed(t *testing.T) {
	p := writeCheck(t, "ok 214 - largeobject\nok 215 - with\n\nAll 215 tests passed.\n")
	passed, failed, names, ran := parseCheck(p)
	if !ran || passed != 215 || failed != 0 || len(names) != 0 {
		t.Errorf("passed=%d failed=%d names=%v ran=%v", passed, failed, names, ran)
	}
}

// NAMED, NOT COUNTED. "3 of 215 failed" sends somebody to a log to find out
// which three, and which three is the whole answer -- especially for a patch
// that rewrites the expected output of planner tests.
func TestParseCheckNamesTheFailures(t *testing.T) {
	p := writeCheck(t, `ok 12    - select
not ok 13    - join
not ok 14    - subselect
ok 15    - union
not ok 16    - equivclass

3 of 215 tests failed.
`)
	passed, failed, names, ran := parseCheck(p)
	if !ran {
		t.Fatal("the suite ran and was not recorded as having run")
	}
	if failed != 3 || passed != 212 {
		t.Errorf("passed=%d failed=%d, want 212 and 3", passed, failed)
	}
	want := map[string]bool{"join": true, "subselect": true, "equivclass": true}
	if len(names) != 3 {
		t.Fatalf("names = %v, want the three that failed", names)
	}
	for _, n := range names {
		if !want[n] {
			t.Errorf("unexpected failure name %q", n)
		}
	}
}

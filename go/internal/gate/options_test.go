package gate

import (
	"os"
	"path/filepath"
	"testing"

	"pgfuzz/internal/logs"
)

// THE CONFIGURED TIMEOUT COMES FROM THE .options FILE FIRST.
//
// The shell read <target>.options, then -timeout= in the log, then 25. This
// read only the log, so a workspace configured at timeout=60 was judged at 25
// and cried wolf on every unit between the two -- and the finding IS that the
// configured and observed values disagree, so taking the configured one from
// the weaker source undermines the comparison.
func TestSlowUnitsReadsTheOptionsFile(t *testing.T) {
	build := t.TempDir()
	write := func(body string) {
		if err := os.WriteFile(filepath.Join(build, "jsonb_fuzzer.options"),
			[]byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("[libfuzzer]\ntimeout = 60\ndict = /out/x.dict\n")

	// 40s is under the configured 60 and over the default 25.
	s := logs.Stats{Target: "jsonb_fuzzer", SlowestUnit: 40}
	if v := SlowUnitsIn(s, build); v.Failed {
		t.Errorf("cried wolf against the default instead of the configured 60: %v", v.Detail)
	}
	// Over the configured value is a real finding.
	s.SlowestUnit = 90
	if v := SlowUnitsIn(s, build); !v.Failed {
		t.Error("a unit past the configured timeout was not reported")
	}
}

// THE LOG STILL WINS when it carries the invocation: that is what the run
// actually used, and the .options file may have changed since.
func TestSlowUnitsPrefersTheLogsOwnTimeout(t *testing.T) {
	build := t.TempDir()
	os.WriteFile(filepath.Join(build, "a_fuzzer.options"),
		[]byte("[libfuzzer]\ntimeout = 60\n"), 0o644)

	s := logs.Stats{Target: "a_fuzzer", SlowestUnit: 40, Timeout: 25}
	if v := SlowUnitsIn(s, build); !v.Failed {
		t.Error("the timeout the run was invoked with was ignored")
	}
}

// ONLY THE [libfuzzer] SECTION carries libFuzzer flags; a timeout under
// another section is not one.
func TestOptionsTimeoutIgnoresOtherSections(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "x.options")
	os.WriteFile(p, []byte("[asan]\ntimeout = 900\n"), 0o644)
	if got := optionsTimeout(p); got != 0 {
		t.Errorf("got %d from an [asan] section, want 0", got)
	}
	os.WriteFile(p, []byte("[libfuzzer]\ntimeout = 45\n"), 0o644)
	if got := optionsTimeout(p); got != 45 {
		t.Errorf("got %d, want 45", got)
	}
	// A missing file is not an error; 25 remains the fallback above.
	if got := optionsTimeout(filepath.Join(d, "nope")); got != 0 {
		t.Errorf("got %d for a missing file", got)
	}
}

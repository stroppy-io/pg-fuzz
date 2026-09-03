package logs

import (
	"strings"
	"testing"
)

// Three states, not two. Conflating them cost this project twice, in opposite
// directions: once failing all twelve builds of a campaign in four minutes,
// once letting four dead targets survive a whole campaign.
func TestStartupTellsDiedFromStalledFromFuzzed(t *testing.T) {
	for _, c := range []struct {
		name string
		log  string
		want Startup
	}{
		{"fuzzed", "Running with entropic power schedule\n#1000 INITED cov: 1 ft: 1 corp: 1/1b\n" +
			"Done 5000 runs in 10 second(s)\n", Fuzzed},
		{"inited but never fuzzed", "Running with entropic power schedule\n" +
			"#1000 INITED cov: 1 ft: 1 corp: 1/1b\n", Inited},
		{"died before libFuzzer spoke", "TRAP: failed Assert(\"MyProc != NULL\")\n" +
			"==21==ERROR: AddressSanitizer: ABRT\n", NoEvidence},
		{"aborted on the initial corpus", "INFO: Seed: 12345\n" +
			"ERROR: libFuzzer: no interesting inputs were found\n", Inited},
		{"nothing at all", "", NoEvidence},
	} {
		got := Parse(strings.NewReader(c.log)).Startup()
		if got != c.want {
			t.Errorf("%s: Startup = %v, want %v", c.name, got, c.want)
		}
	}
}

// libFuzzer's own abort strings are matched exactly, and are deliberately not
// suppressible: a target that says either did not fuzz, whatever a floor says.
func TestAbortStringsAreRecognised(t *testing.T) {
	for _, l := range []string{
		"ERROR: libFuzzer: a leak has been found in the initial corpus",
		"ERROR: libFuzzer: no interesting inputs were found",
	} {
		if !Parse(strings.NewReader(l + "\n")).Aborted {
			t.Errorf("not recognised as an abort: %s", l)
		}
	}
	if Parse(strings.NewReader("Done 10 runs in 1 second(s)\n")).Aborted {
		t.Error("a healthy run was read as an abort")
	}
}

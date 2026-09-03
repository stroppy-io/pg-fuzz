package build

import (
	"reflect"
	"testing"
)

func TestSelectedEmptyMeansEverything(t *testing.T) {
	built := []string{"a_fuzzer", "b_fuzzer"}
	got, missing := Selected(built, "")
	if !reflect.DeepEqual(got, built) || missing != nil {
		t.Errorf("Selected(built, \"\") = %v, %v; empty must mean every built target",
			got, missing)
	}
	// Whitespace is still empty: `targets=   ` is a blank key, not a request
	// for a target named "".
	if got, _ := Selected(built, "   \t "); !reflect.DeepEqual(got, built) {
		t.Errorf("a whitespace-only value = %v, want every target", got)
	}
}

func TestSelectedNarrowsInTheConfigsOrder(t *testing.T) {
	built := []string{"a_fuzzer", "b_fuzzer", "c_fuzzer"}
	got, missing := Selected(built, "c_fuzzer a_fuzzer")
	if want := []string{"c_fuzzer", "a_fuzzer"}; !reflect.DeepEqual(got, want) {
		t.Errorf("Selected = %v, want %v -- the order somebody wrote down", got, want)
	}
	if missing != nil {
		t.Errorf("missing = %v, want none", missing)
	}
}

// A CONFIG CANNOT CONJURE A BINARY. A listed target that was not built is
// dropped and REPORTED, so "I asked for three and three exist" is
// distinguishable from "I asked for three and two do".
func TestSelectedReportsWhatWasNotBuilt(t *testing.T) {
	got, missing := Selected([]string{"a_fuzzer"}, "a_fuzzer z_fuzzer")
	if want := []string{"a_fuzzer"}; !reflect.DeepEqual(got, want) {
		t.Errorf("Selected = %v, want %v", got, want)
	}
	if want := []string{"z_fuzzer"}; !reflect.DeepEqual(missing, want) {
		t.Errorf("missing = %v, want %v", missing, want)
	}
}

// Asking only for targets that do not exist selects nothing, and says so.
// Falling back to everything would run the opposite of what was asked.
func TestSelectedNoneMatch(t *testing.T) {
	got, missing := Selected([]string{"a_fuzzer"}, "y_fuzzer z_fuzzer")
	if len(got) != 0 {
		t.Errorf("Selected = %v, want nothing", got)
	}
	if len(missing) != 2 {
		t.Errorf("missing = %v, want both names", missing)
	}
}

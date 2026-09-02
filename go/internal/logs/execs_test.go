package logs

import "strings"

import "testing"

// On an ASan build libFuzzer prints its stat block TWICE per job -- once
// normally and once when LeakSanitizer reports at exit -- so summing
// stat::number_of_executed_units doubles the count. "Done N runs" is printed
// once per worker and is the target's own report, which is why the old driver
// preferred it. Every -add exec figure feeds the ratchet floors.
func TestExecsPreferDoneOverDoubledStatBlocks(t *testing.T) {
	log := `#1000 INITED cov: 10 ft: 20 corp: 5/100b
Done 1000 runs in 10 second(s)
stat::number_of_executed_units: 1000
stat::new_units_added:          3
stat::number_of_executed_units: 1000
stat::new_units_added:          3
`
	s := Parse(strings.NewReader(log))
	if s.Execs != 1000 {
		t.Errorf("Execs = %d, want 1000 (the stat:: sum is 2000 on ASan)", s.Execs)
	}
}

// A run stopped by the watchdog prints its stats and no Done line. Those are
// exactly the targets whose floors would otherwise become unverifiable, so the
// stat:: sum has to remain the fallback.
func TestExecsFallBackToStatWhenNoDoneLine(t *testing.T) {
	log := `#1000 INITED cov: 10 ft: 20 corp: 5/100b
stat::number_of_executed_units: 777
`
	s := Parse(strings.NewReader(log))
	if s.Execs != 777 {
		t.Errorf("Execs = %d, want 777 from the stat:: fallback", s.Execs)
	}
}

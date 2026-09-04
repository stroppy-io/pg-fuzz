package fuzz

import "testing"

// EVERY SWEEP APPLIES THE TUNED TABLE, not only a soak.
//
// spi_query_fuzzer and simple_query_fuzzer need 150s and 200s before they are
// past corpus replay; the shell gave them that in every sweep. The port read
// the table in soak alone, so every campaign round handed those two the flat
// -time and produced their exec counts on a different time basis than the
// floors they are judged against.
func TestSweepAppliesPerTargetBudgets(t *testing.T) {
	b := Budgets{"ws": {"spi_query_fuzzer": 150}}

	if got := b.For("ws", "spi_query_fuzzer", 45); got != 150 {
		t.Errorf("tuned target got %d, want its table entry 150", got)
	}
	if got := b.For("ws", "jsonb_fuzzer", 45); got != 45 {
		t.Errorf("untuned target got %d, want the flat budget 45", got)
	}
	// An absent table leaves an UNKNOWN target on the flat budget -- never on
	// zero, which would be an instant slice. A known-slow one keeps its floor;
	// see TestSlowDefaultsSurviveAnEmptyTable.
	var none Budgets
	if got := none.For("ws", "jsonb_fuzzer", 45); got != 45 {
		t.Errorf("with no table got %d, want the flat budget", got)
	}
}

// The known-slow floor still applies when the table has no row, which is what
// stops a fresh host giving the two slow targets a 45-second slice.
func TestSlowDefaultsSurviveAnEmptyTable(t *testing.T) {
	var none Budgets
	for tgt, want := range SlowDefaults {
		if got := none.For("ws", tgt, 45); got < want {
			t.Errorf("%s got %d, want at least its known-slow floor %d", tgt, got, want)
		}
	}
}

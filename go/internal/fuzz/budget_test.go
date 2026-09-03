package fuzz

import (
	"os"
	"path/filepath"
	"testing"
)

// The tuner that maintains this table survived the port -- `corpus -autocap
// -tune-budget` writes it -- and the reader did not, so every target got one
// number. That is wrong in both directions: a target replaying a large corpus
// needs longer before it fuzzes at all, and a fast one given the slow one's
// budget wastes the difference.
func TestBudgetsPreferTunedThenKnownSlowThenDefault(t *testing.T) {
	p := filepath.Join(t.TempDir(), "target-budgets.tsv")
	body := "# ws\ttarget\tseconds\n" +
		"pg17-add\tjsonb_fuzzer\t45\n" +
		"pg17-add\tspi_query_fuzzer\t600\n" +
		"other-ws\tjsonb_fuzzer\t999\n"
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	b := LoadBudgets(p)

	if got := b.For("pg17-add", "jsonb_fuzzer", 90); got != 45 {
		t.Errorf("tuned value ignored: %d", got)
	}
	// Per (workspace, target): the same target replays different corpora in
	// different workspaces.
	if got := b.For("other-ws", "jsonb_fuzzer", 90); got != 999 {
		t.Errorf("the wrong workspace's budget was used: %d", got)
	}
	// A tuned value wins over the known-slow default.
	if got := b.For("pg17-add", "spi_query_fuzzer", 90); got != 600 {
		t.Errorf("tuned value lost to the slow default: %d", got)
	}
	// No row: the measured slow default.
	if got := b.For("pg17-und", "spi_query_fuzzer", 90); got != 150 {
		t.Errorf("known-slow default ignored: %d", got)
	}
	// Nothing known at all: the caller's number.
	if got := b.For("pg17-und", "jsonb_fuzzer", 90); got != 90 {
		t.Errorf("default ignored: %d", got)
	}
}

// The table is an optimisation over a default that is always available.
// Refusing to run without it would turn a tuning aid into a dependency.
func TestMissingBudgetsFileIsNotAnError(t *testing.T) {
	b := LoadBudgets(filepath.Join(t.TempDir(), "nope.tsv"))
	if got := b.For("ws", "a_fuzzer", 90); got != 90 {
		t.Errorf("a missing table changed the budget: %d", got)
	}
	if got := b.For("ws", "spi_query_fuzzer", 90); got != 150 {
		t.Errorf("a missing table lost the slow default: %d", got)
	}
}

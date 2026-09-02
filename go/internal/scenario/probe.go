package scenario

import "fmt"

// Probes are the consistency checks run after the load and after every step.
// They are what actually finds these defects: the perturbations put the
// storage engine into an odd state, and the probes ask whether it still
// answers correctly.
//
// The set is derived from the failure strings in the recorded findings, which
// name the probe that fired:
//
//	after_load/t0: probe failed: SELECT count(*) FROM t0 WHERE v > 0
//	after_set_tablespace:t0/t0: expected 6000 rows, got 0
//	after_set_tablespace:t0/t0: access paths disagree -- seqscan='N' indexscan='M'
//	after_delete_half:t1/t1: orioledb_tbl_check: server closed the connection
//
// FOUR CHECKS, AND THE THIRD IS THE ONE THAT MATTERS MOST.
//
// A count that disagrees between a sequential scan and an index scan is the
// only probe here that catches a WRONG ANSWER rather than a crash. The
// SET TABLESPACE finding -- indexes silently emptied, queries returning zero
// rows with no error and no log line -- is invisible to every other check.
// A storage engine that crashes is caught by anything; one that answers
// confidently and wrongly is caught only by asking the same question twice.
type Probe struct {
	Name string
	SQL  string
	Want string // "rows" compares against the expected row count
}

// ProbesFor returns the checks to run against one table.
func ProbesFor(t Table) []Probe {
	q := fmt.Sprintf("SELECT count(*) FROM %s WHERE v > 0", t.Name)
	out := []Probe{
		{
			Name: "count",
			SQL:  fmt.Sprintf("SELECT count(*) FROM %s", t.Name),
			Want: "rows",
		},
		{
			Name: "predicate",
			SQL:  q,
		},
		{
			Name: "range",
			SQL:  fmt.Sprintf("SELECT count(*) FROM %s WHERE i BETWEEN 1 AND 100", t.Name),
		},
	}

	// The same question, forced down two different plans. Equal answers or the
	// engine is wrong -- see the type comment.
	out = append(out, Probe{
		Name: "access-paths",
		SQL: fmt.Sprintf(
			"SET enable_seqscan = on; SET enable_indexscan = off; SET enable_bitmapscan = off; %s; "+
				"SET enable_seqscan = off; SET enable_indexscan = on; SET enable_bitmapscan = on; %s; "+
				"RESET enable_seqscan; RESET enable_indexscan; RESET enable_bitmapscan;",
			q, q),
	})

	// OrioleDB ships its own structural check. It is the probe that turns a
	// silently corrupt B-tree into a server that closes the connection, which
	// is how three of the recorded findings present.
	if t.AM == "orioledb" && !t.Partitioned {
		out = append(out, Probe{
			Name: "orioledb_tbl_check",
			SQL:  fmt.Sprintf("SELECT orioledb_tbl_check('%s'::regclass)", t.Name),
		})
	}
	return out
}

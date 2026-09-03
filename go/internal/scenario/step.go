package scenario

import (
	"fmt"
	"strings"
)

// Kind is how a step has to be carried out.
//
// The split matters more than it looks. Most perturbations are SQL and can be
// sent down an open session. A few are not: restart_crash has to kill -9 the
// postmaster and bring it back, concurrent_write needs a second session
// running at the same time as the first. Those are exactly the steps a fuzz
// target cannot express, and they are why these findings need a scenario
// engine at all rather than a corpus of statements.
type Kind int

const (
	SQL        Kind = iota // one or more statements on the main session
	Control                // the driver does something to the server
	Concurrent             // needs a second session, overlapping the first
)

// Plan is what to do for one step.
type Plan struct {
	Kind Kind
	SQL  []string // for SQL and Concurrent
	Ctl  string   // for Control: crash | clean
	Note string   // what this step is for, in one line

	// ChangesRows says this step is SUPPOSED to change the row count.
	//
	// Without it the count probe compares every step against the loaded
	// total, so insert_more and delete_half "fail" every scenario -- which
	// they did, and reported eight reproductions from a broken instrument.
	// With it, a count that moves under a step that should not move it is
	// the finding: SET TABLESPACE emptying secondary indexes is exactly
	// "expected 6000 rows, got 0" from a step that changes nothing.
	ChangesRows bool

	// RowDelta is how much this step changes the count BY, when that is
	// known exactly. It exists because ChangesRows adopts whatever the server
	// reports, and for the transactional shapes that is the one thing it must
	// never do: rollback_insert, savepoint_partial and prepare_2pc are the
	// only oracle for the undo log, and adopting the post-step count installs
	// the very corruption they are there to detect. A step that undoes itself
	// carries no delta at all -- its count must not move.
	RowDelta int

	// Parallel runs this step once per recorded writer instead of once.
	// Only meaningful for Concurrent steps whose statements do not change
	// cardinality.
	Parallel bool
}

// PlanStep turns a recorded step into something executable.
//
// Every op in Ops must be handled here. The test asserts that, so a step this
// does not know about is a build-time-visible gap rather than a scenario that
// quietly runs short -- and a scenario missing a step is a different
// experiment with the same seed number.
func PlanStep(s Step, sc Scenario) (Plan, bool) {
	t := s.Table
	tbl := findTable(sc, t)

	switch s.Op {
	// ---- plain SQL -----------------------------------------------------
	case "analyze":
		return Plan{Kind: SQL, SQL: []string{f("ANALYZE %s;", t)}, Note: "refresh statistics"}, true
	case "vacuum":
		return Plan{Kind: SQL, SQL: []string{f("VACUUM %s;", t)}}, true
	case "vacuum_full":
		return Plan{Kind: SQL, SQL: []string{f("VACUUM FULL %s;", t)}}, true
	case "reindex":
		return Plan{Kind: SQL, SQL: []string{f("REINDEX TABLE %s;", t)}}, true
	case "truncate_refill":
		return Plan{Kind: SQL, SQL: []string{
			f("TRUNCATE %s;", t),
			loadStatement(tbl),
		}, Note: "empty and reload"}, true
	case "delete_half":
		return Plan{Kind: SQL, SQL: []string{f("DELETE FROM %s WHERE i %% 2 = 0;", t)}, ChangesRows: true}, true
	case "update_all":
		return Plan{Kind: SQL, SQL: []string{f("UPDATE %s SET v = v + 1;", t)}}, true
	case "insert_more":
		return Plan{Kind: SQL, SQL: []string{
			stepInsert(tbl, t, rowsOf(tbl)+1, rowsOf(tbl)+1000, "g * 3")},
			ChangesRows: true}, true
	case "upsert":
		return Plan{Kind: SQL, SQL: []string{
			strings.TrimSuffix(stepInsert(tbl, t, 1, 100, "g * 5"), ";") +
				" ON CONFLICT DO NOTHING;"},
			ChangesRows: true}, true
	case "add_column":
		return Plan{Kind: SQL, SQL: []string{f("ALTER TABLE %s ADD COLUMN added_col bigint;", t)}}, true
	case "drop_column":
		return Plan{Kind: SQL, SQL: []string{f("ALTER TABLE %s DROP COLUMN IF EXISTS added_col;", t)}}, true
	case "alter_type":
		return Plan{Kind: SQL, SQL: []string{f("ALTER TABLE %s ALTER COLUMN v TYPE numeric;", t)}}, true
	case "set_tablespace":
		return Plan{Kind: SQL, SQL: []string{f("ALTER TABLE %s SET TABLESPACE %s;", t, otherTablespace(tbl))},
			Note: "move the table; the indexes are the interesting part"}, true
	case "move_index":
		return Plan{Kind: SQL, SQL: []string{f(
			"ALTER INDEX ALL IN TABLESPACE %s OWNED BY CURRENT_USER SET TABLESPACE %s;",
			firstTablespace(tbl), otherTablespace(tbl))}}, true
	case "attach_partition":
		return Plan{Kind: SQL, SQL: []string{
			f("CREATE TABLE %s_extra (LIKE %s INCLUDING ALL);", t, t),
			f("ALTER TABLE %s ATTACH PARTITION %s_extra FOR VALUES FROM (900000) TO (1000000);", t, t),
		}}, true
	case "detach_partition":
		return Plan{Kind: SQL, SQL: []string{f("ALTER TABLE %s DETACH PARTITION %s_p1;", t, t)}}, true
	case "move_across_partition":
		return Plan{Kind: SQL, SQL: []string{f(
			"UPDATE %s SET i = i + %d WHERE i %% 1000 = 1;", t, rowsOf(tbl))},
			Note: "force rows over the partition boundary"}, true

	// ---- transactional shapes ------------------------------------------
	case "rollback_insert":
		return Plan{Kind: SQL, SQL: []string{
			"BEGIN;",
			stepInsert(tbl, t, rowsOf(tbl)+2000, rowsOf(tbl)+2050, "g"),
			"ROLLBACK;",
		}}, true
	case "rollback_delete":
		return Plan{Kind: SQL, SQL: []string{
			"BEGIN;", f("DELETE FROM %s;", t), "ROLLBACK;",
		}}, true
	case "rollback_ddl":
		return Plan{Kind: SQL, SQL: []string{
			"BEGIN;", f("ALTER TABLE %s ADD COLUMN rolled bigint;", t), "ROLLBACK;",
		}}, true
	case "savepoint_partial":
		return Plan{Kind: SQL, SQL: []string{
			"BEGIN;",
			stepInsert(tbl, t, rowsOf(tbl)+3000, rowsOf(tbl)+3020, "g"),
			"SAVEPOINT sp;",
			f("DELETE FROM %s WHERE i > %d;", t, rowsOf(tbl)+3010),
			"ROLLBACK TO SAVEPOINT sp;",
			"COMMIT;",
		}, RowDelta: 21}, true
	case "prepare_2pc":
		return Plan{Kind: SQL, SQL: []string{
			"BEGIN;",
			stepInsert(tbl, t, rowsOf(tbl)+4000, rowsOf(tbl)+4010, "g"),
			f("PREPARE TRANSACTION 'p_%s';", t),
			f("COMMIT PREPARED 'p_%s';", t),
		}, RowDelta: 11}, true
	case "serializable_write":
		return Plan{Kind: SQL, SQL: []string{
			"BEGIN ISOLATION LEVEL SERIALIZABLE;",
			f("UPDATE %s SET v = v + 2 WHERE i < 100;", t),
			"COMMIT;",
		}}, true
	case "repeatable_read_write":
		return Plan{Kind: SQL, SQL: []string{
			"BEGIN ISOLATION LEVEL REPEATABLE READ;",
			f("UPDATE %s SET v = v + 3 WHERE i < 100;", t),
			"COMMIT;",
		}}, true
	case "churn_evict":
		return Plan{Kind: SQL, SQL: []string{f(
			"UPDATE %s SET v = v + 1 WHERE i %% 3 = 0;", t),
			f("DELETE FROM %s WHERE i %% 7 = 0;", t),
		}, Note: "dirty enough pages to force eviction"}, true

	// ---- needs a second session ----------------------------------------
	case "concurrent_write":
		// Parallel across the scenario's writers: this is the step the
		// recorded `writers` count is about. An UPDATE, so N sessions do not
		// disturb the cardinality oracle -- unlike the DDL shapes below, where
		// a second session would collide with the first by construction rather
		// than by contention.
		return Plan{Kind: Concurrent, Parallel: true, SQL: []string{
			f("UPDATE %s SET v = v + 1 WHERE i %% 5 = 0;", t)}}, true
	case "concurrent_ddl":
		return Plan{Kind: Concurrent, SQL: []string{
			f("ALTER TABLE %s ADD COLUMN conc bigint;", t),
			f("ALTER TABLE %s DROP COLUMN conc;", t)}}, true
	case "concurrent_checkpoint":
		return Plan{Kind: Concurrent, SQL: []string{"CHECKPOINT;"}}, true

	// ---- the driver acts on the server ---------------------------------
	case "checkpoint":
		return Plan{Kind: SQL, SQL: []string{"CHECKPOINT;"}}, true
	case "restart_clean":
		return Plan{Kind: Control, Ctl: "clean",
			Note: "stop and start; everything should survive"}, true
	case "restart_crash":
		return Plan{Kind: Control, Ctl: "crash",
			Note: "kill -9 the postmaster: recovery replays WAL, and what it " +
				"does NOT rebuild is where these findings live"}, true
	}
	return Plan{}, false
}

func f(format string, a ...any) string { return fmt.Sprintf(format, a...) }

// stepInsert builds an INSERT that satisfies the table's NOT NULL columns.
//
// A composite_typed table has a k column in its primary key, NOT NULL, and a
// step that inserts only (i, j, v) dies on it -- which is what happened, and
// it aborted three scenarios before they reached the step that matters. The
// failure even looks plausible ("null value in column k"), which is worse
// than a crash: it reads like a finding.
func stepInsert(t *Table, name string, from, to int, vexpr string) string {
	cols := "i, j, v"
	vals := fmt.Sprintf("g, g %% 97, %s", vexpr)
	if t != nil && t.PK == "composite_typed" && t.PKExtra != "" {
		cols += ", k"
		vals += ", " + loadExpr(t.PKExtra)
	}
	return fmt.Sprintf("INSERT INTO %s (%s) SELECT %s FROM generate_series(%d, %d) g;",
		name, cols, vals, from, to)
}

func findTable(sc Scenario, name string) *Table {
	for i := range sc.Tables {
		if sc.Tables[i].Name == name {
			return &sc.Tables[i]
		}
	}
	return nil
}

func rowsOf(t *Table) int {
	if t == nil || t.Rows == 0 {
		return 1000
	}
	return t.Rows
}

func firstTablespace(t *Table) string {
	if t != nil && t.Tablespace != nil && *t.Tablespace != "" {
		return *t.Tablespace
	}
	return "ts_a"
}

// otherTablespace is the one the table is NOT in -- moving it to where it
// already is would exercise nothing.
func otherTablespace(t *Table) string {
	if firstTablespace(t) == "ts_a" {
		return "ts_b"
	}
	return "ts_a"
}

// loadStatement is the INSERT for a table, reused by truncate_refill.
func loadStatement(t *Table) string {
	if t == nil {
		return "-- no such table"
	}
	return renderLoad(*t)
}

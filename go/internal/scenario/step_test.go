package scenario

import "testing"

// The transactional shapes are the only oracle for the undo log, and they must
// state their outcome in advance. ChangesRows adopts whatever the server
// reports, so marking these with it made the driver install the very
// corruption they exist to detect: a rollback that leaves rows behind had its
// wrong count read back and recorded as expected.
func TestTransactionalShapesPredictRatherThanAdopt(t *testing.T) {
	sc := Scenario{Tables: []Table{{Name: "t", AM: "orioledb", Rows: 1000}}}
	for _, c := range []struct {
		op    string
		delta int
		why   string
	}{
		{"rollback_insert", 0, "inserts then rolls back: the count must not move"},
		{"rollback_delete", 0, "deletes then rolls back: the count must not move"},
		{"rollback_ddl", 0, "adds a column then rolls back"},
		{"savepoint_partial", 21, "21 rows inserted; the DELETE is undone to the savepoint"},
		{"prepare_2pc", 11, "11 rows, prepared then committed"},
	} {
		p, ok := PlanStep(Step{Op: c.op, Table: "t"}, sc)
		if !ok {
			t.Errorf("%s: no plan", c.op)
			continue
		}
		if p.ChangesRows {
			t.Errorf("%s adopts the server's count; it must predict (%s)", c.op, c.why)
		}
		if p.RowDelta != c.delta {
			t.Errorf("%s RowDelta = %d, want %d (%s)", c.op, p.RowDelta, c.delta, c.why)
		}
	}
}

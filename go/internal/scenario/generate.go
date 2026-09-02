package scenario

import (
	"math/rand"
)

// Generate builds a scenario from a seed.
//
// NOT BIT-COMPATIBLE WITH THE PYTHON GENERATOR, and it does not need to be.
// The recorded findings carry the whole scenario as JSON rather than just the
// seed number -- precisely because the generator changed and seed 131 stopped
// producing what seed 131 once produced. Replay reads those files; this
// produces NEW scenarios. Conflating the two is what made a recorded seed
// number look like a reproducer when it was only a label.
//
// Deterministic per seed all the same: two runs of the same seed must build
// the same experiment, or a scenario that fails cannot be re-run.
func Generate(seed int, orioledb bool) Scenario {
	r := rand.New(rand.NewSource(int64(seed)))
	s := Scenario{Seed: seed, OrioleDB: orioledb, Writers: 1 + r.Intn(2)}

	if orioledb {
		// The values the recorded corpus actually uses. "warning" was
		// invented and PostgreSQL rejects it, which failed every generated
		// scenario in setup -- correctly reported as "could not run" rather
		// than as findings, but three wasted runs all the same. The
		// vocabulary comes from the fixtures, like everything else here.
		s.OrioleSettings = map[string]any{
			"orioledb.serializable":     pick(r, []any{"error", "table_lock", "repeatable_read"}),
			"orioledb.default_compress": pick(r, []any{-1, 1, 5}),
		}
	}
	// Tablespaces exist to be moved between, so either both or neither.
	useTS := r.Intn(2) == 0
	s.WarmDefaultTablespace = useTS && r.Intn(3) == 0

	n := 1 + r.Intn(3)
	for i := 0; i < n; i++ {
		s.Tables = append(s.Tables, genTable(r, i, orioledb, useTS))
	}
	s.Steps = genSteps(r, s.Tables)
	return s
}

var (
	pkKinds    = []string{"single", "composite", "composite_typed", "none"}
	pkExtras   = []string{"date", "smallint", "int", "numeric", "timestamptz", "double precision"}
	extraTypes = []string{"timestamptz", "bigint", "bigint[]", "text", "uuid", "numeric", "jsonb", "boolean"}
	indexKinds = []string{"btree", "hash", "brin", "gin", "spgist", "partial", "expression", "multicolumn", "unique"}
	rowCounts  = []int{500, 2000, 5000, 6000, 50000}
)

func genTable(r *rand.Rand, i int, orioledb, useTS bool) Table {
	t := Table{
		Name:        "t" + itoa(i),
		AM:          "heap",
		PK:          pkKinds[r.Intn(len(pkKinds))],
		PKExtra:     pkExtras[r.Intn(len(pkExtras))],
		Rows:        rowCounts[r.Intn(len(rowCounts))],
		Partitioned: r.Intn(4) == 0,
		Unlogged:    r.Intn(6) == 0,
		Wide:        r.Intn(3) == 0,
		Generated:   r.Intn(5) == 0,
	}
	if orioledb && r.Intn(4) != 0 {
		t.AM = "orioledb"
		// OrioleDB does not support unlogged tables, and a scenario that
		// cannot be built tests nothing. Same class as compress on a heap
		// table: a combination the engine rejects, which shows up as a setup
		// failure rather than as a defect.
		t.Unlogged = false
		// compress is an OrioleDB storage parameter and is not emitted on a
		// heap table -- see withClause. Recorded on both by the Python
		// generator, which is why the renderer has to guard it.
		if r.Intn(2) == 0 {
			c := []int{-1, 1, 5}[r.Intn(3)]
			t.Compress = &c
		}
	}
	for j, k := 0, r.Intn(4); j < k; j++ {
		ty := extraTypes[r.Intn(len(extraTypes))]
		if !contains(t.ExtraTypes, ty) {
			t.ExtraTypes = append(t.ExtraTypes, ty)
		}
	}
	for j, k := 0, r.Intn(4); j < k; j++ {
		kind := indexKinds[r.Intn(len(indexKinds))]
		if !contains(t.Indexes, kind) {
			t.Indexes = append(t.Indexes, kind)
		}
	}
	if useTS {
		a, b := "ts_a", "ts_b"
		if r.Intn(2) == 0 {
			a, b = b, a
		}
		t.Tablespace, t.IndexTablespace = &a, &b
	}
	return t
}

// genSteps picks perturbations that make sense for the tables built.
//
// A step naming a table that cannot take it -- attach_partition on an
// unpartitioned table -- fails at the step rather than at the defect, and a
// scenario that dies in setup tests nothing.
func genSteps(r *rand.Rand, tables []Table) []Step {
	var out []Step
	n := 3 + r.Intn(8)
	for i := 0; i < n; i++ {
		t := tables[r.Intn(len(tables))]
		op := Ops[r.Intn(len(Ops))]
		switch op {
		case "attach_partition", "detach_partition", "move_across_partition":
			if !t.Partitioned {
				continue
			}
		case "set_tablespace", "move_index":
			if t.Tablespace == nil {
				continue
			}
		case "prepare_2pc":
			// OrioleDB rejects PREPARE TRANSACTION outright in a transaction
			// touching an orioledb table, so the step would fail on the
			// engine's own limitation rather than on a defect.
			if t.AM == "orioledb" {
				continue
			}
		}
		out = append(out, Step{Op: op, Table: t.Name})
	}
	if len(out) == 0 {
		out = append(out, Step{Op: "vacuum", Table: tables[0].Name})
	}
	return out
}

func pick(r *rand.Rand, xs []any) any { return xs[r.Intn(len(xs))] }

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

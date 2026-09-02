package scenario

import (
	"fmt"
	"strings"
)

// RenderSetup emits the setup SQL for a scenario: tablespaces, database
// settings, tables, indexes and the load. Not the perturbation steps -- those
// are applied by the driver against a live server, which is why the recorded
// .sql files say "setup only" and why a seedN.sql alone does not reproduce a
// finding.
//
// This exists to be compared, byte for byte, against the 27 recorded .sql
// files. That comparison is the port's real test: it needs no server, no
// container and no OrioleDB, and it fails loudly on the kind of small
// divergence -- a missing TABLESPACE, a partition boundary off by one -- that
// would otherwise turn into "the finding stopped reproducing" months later.
func RenderSetup(s Scenario) string {
	var b strings.Builder

	// Tablespaces first, and both of them whenever either is used: a table
	// naming ts_b cannot be created before ts_b exists, and the recorded SQL
	// declares the pair unconditionally.
	// warm_default_tablespace: the generator creates and drops a throwaway
	// table first, so the default tablespace is not cold when the real load
	// starts. It is the first statement when set.
	if s.WarmDefaultTablespace {
		b.WriteString("CREATE TABLE warmup (i int);\n")
		b.WriteString("INSERT INTO warmup VALUES (1);\n")
	}
	if usesTablespaces(s) {
		b.WriteString("CREATE TABLESPACE ts_a LOCATION '';\n")
		b.WriteString("CREATE TABLESPACE ts_b LOCATION '';\n")
	}
	if s.DefaultTablespace != nil && *s.DefaultTablespace != "" {
		fmt.Fprintf(&b, "ALTER DATABASE postgres SET default_tablespace = %s;\n", *s.DefaultTablespace)
	}
	for _, k := range orderedKeys(s.OrioleSettings) {
		fmt.Fprintf(&b, "ALTER DATABASE postgres SET %s = %v;\n", k, s.OrioleSettings[k])
	}

	for _, t := range s.Tables {
		b.WriteString(renderTable(t))
	}
	return b.String()
}

func usesTablespaces(s Scenario) bool {
	if s.DefaultTablespace != nil {
		return true
	}
	for _, t := range s.Tables {
		if t.Tablespace != nil || t.IndexTablespace != nil {
			return true
		}
	}
	return false
}

// orderedKeys keeps oriole_settings in the order the recorded SQL has them.
// Go maps do not preserve insertion order and the corpus only ever carries
// these two, so the order is pinned rather than sorted -- sorting would put
// default_compress first and every golden would differ by two lines.
func orderedKeys(m map[string]any) []string {
	pref := []string{"orioledb.serializable", "orioledb.default_compress"}
	var out []string
	for _, k := range pref {
		if _, ok := m[k]; ok {
			out = append(out, k)
		}
	}
	for k := range m {
		found := false
		for _, p := range pref {
			if k == p {
				found = true
			}
		}
		if !found {
			out = append(out, k)
		}
	}
	return out
}

func renderTable(t Table) string {
	var b strings.Builder

	cols := []string{"i bigint NOT NULL", "j bigint NOT NULL", "v bigint NOT NULL"}
	// pk_extra materialises as a column only for composite_typed -- every
	// other kind carries the field and does not use it.
	if t.PK == "composite_typed" && t.PKExtra != "" {
		cols = append(cols, "k "+t.PKExtra+" NOT NULL")
	}
	for i, ty := range t.ExtraTypes {
		cols = append(cols, fmt.Sprintf("x%d %s", i, ty))
	}
	if t.Wide {
		cols = append(cols, "payload text")
	}
	if t.Generated {
		cols = append(cols, "gen bigint GENERATED ALWAYS AS (i * 2) STORED")
	}
	if pk := pkClause(t); pk != "" {
		cols = append(cols, pk)
	}

	kw := "CREATE TABLE"
	if t.Unlogged {
		kw = "CREATE UNLOGGED TABLE"
	}
	fmt.Fprintf(&b, "%s %s (%s)", kw, t.Name, strings.Join(cols, ", "))
	if t.Partitioned {
		b.WriteString(" PARTITION BY RANGE (i)")
	} else {
		fmt.Fprintf(&b, " USING %s", t.AM)
		b.WriteString(withClause(t))
	}
	b.WriteString(tsClause(t.Tablespace))
	b.WriteString(";\n")

	if t.Partitioned {
		// Two partitions, split at rows/2+1, MINVALUE..MAXVALUE at the ends.
		mid := t.Rows/2 + 1
		for i, bounds := range [][2]string{
			{"MINVALUE", fmt.Sprint(mid)},
			{fmt.Sprint(mid), "MAXVALUE"},
		} {
			fmt.Fprintf(&b, "%s %s_p%d PARTITION OF %s FOR VALUES FROM (%s) TO (%s) USING %s%s%s;\n",
				kw, t.Name, i, t.Name, bounds[0], bounds[1], t.AM,
				withClause(t), tsClause(t.Tablespace))
		}
	}

	for _, kind := range t.Indexes {
		b.WriteString(renderIndex(t, kind))
	}
	b.WriteString(renderLoad(t))
	return b.String()
}

func pkClause(t Table) string {
	switch t.PK {
	case "single":
		return "PRIMARY KEY (i)"
	case "composite":
		return "PRIMARY KEY (i, j)"
	case "composite_typed":
		return "PRIMARY KEY (i, k)"
	default: // "none"
		return ""
	}
}

// withClause is the storage parameter list. Only compress appears in the
// corpus, and only on orioledb tables.
func withClause(t Table) string {
	// Only on orioledb: compress is an OrioleDB storage parameter, and the
	// generator records it on heap tables too without ever emitting it. A
	// heap table with WITH (compress = 5) fails to create.
	if t.Compress == nil || t.AM != "orioledb" {
		return ""
	}
	return fmt.Sprintf(" WITH (compress = %d)", *t.Compress)
}

func tsClause(ts *string) string {
	if ts == nil || *ts == "" {
		return ""
	}
	return " TABLESPACE " + *ts
}

func renderIndex(t Table, kind string) string {
	name := fmt.Sprintf("%s_%s_idx", t.Name, kind)
	ts := tsClause(t.IndexTablespace)

	switch kind {
	case "gin":
		// gin needs a column whose type it supports, and the only one the
		// generator ever produces is bigint[]. With none the index is SKIPPED,
		// not emitted against v -- a table with gin in its list and no array
		// column has no gin index in the recorded SQL. Emitting one anyway
		// would fail at CREATE and change what every later step sees.
		col := firstOfType(t, "bigint[]")
		if col == "" {
			return ""
		}
		return fmt.Sprintf("CREATE INDEX %s ON %s USING gin (%s)%s;\n", name, t.Name, col, ts)
	case "spgist":
		col := firstOfType(t, "text")
		if col == "" {
			return ""
		}
		return fmt.Sprintf("CREATE INDEX %s ON %s USING spgist (%s)%s;\n", name, t.Name, col, ts)
	case "brin", "hash":
		return fmt.Sprintf("CREATE INDEX %s ON %s USING %s (v)%s;\n", name, t.Name, kind, ts)
	case "btree":
		return fmt.Sprintf("CREATE INDEX %s ON %s (v)%s;\n", name, t.Name, ts)
	case "multicolumn":
		return fmt.Sprintf("CREATE INDEX %s ON %s (j, v)%s;\n", name, t.Name, ts)
	case "expression":
		return fmt.Sprintf("CREATE INDEX %s ON %s ((v * 2))%s;\n", name, t.Name, ts)
	case "partial":
		return fmt.Sprintf("CREATE INDEX %s ON %s (v)%s WHERE v > 0;\n", name, t.Name, ts)
	case "unique":
		return fmt.Sprintf("CREATE UNIQUE INDEX %s ON %s (i, j)%s;\n", name, t.Name, ts)
	}
	return fmt.Sprintf("-- UNKNOWN INDEX KIND %q\n", kind)
}

// firstOfType names the first extra column of this type, or "" if the table
// has none.
func firstOfType(t Table, ty string) string {
	for i, e := range t.ExtraTypes {
		if e == ty {
			return fmt.Sprintf("x%d", i)
		}
	}
	return ""
}

func renderLoad(t Table) string {
	cols := []string{"i", "j", "v"}
	vals := []string{"g", "g %% 97", "g * 2"}
	if t.PK == "composite_typed" && t.PKExtra != "" {
		cols = append(cols, "k")
		vals = append(vals, loadExpr(t.PKExtra))
	}
	for i, ty := range t.ExtraTypes {
		cols = append(cols, fmt.Sprintf("x%d", i))
		vals = append(vals, loadExpr(ty))
	}
	if t.Wide {
		cols = append(cols, "payload")
		vals = append(vals, "repeat('x', 2000)")
	}
	return fmt.Sprintf("INSERT INTO %s (%s) SELECT %s FROM generate_series(1, %d) g;\n",
		t.Name, strings.Join(cols, ", "),
		strings.ReplaceAll(strings.Join(vals, ", "), "%%", "%"), t.Rows)
}

// loadExpr is the value expression for a column of this type.
func loadExpr(ty string) string {
	switch ty {
	case "timestamptz":
		return "'2020-01-01'::timestamptz + (g || ' seconds')::interval"
	case "bigint[]":
		return "ARRAY[g, g + 1]"
	case "text":
		return "'r' || g"
	case "bigint":
		return "g"
	case "numeric":
		return "(g::numeric / 7)"
	case "uuid":
		return "md5(g::text)::uuid"
	case "date":
		return "'2020-01-01'::date + (g %% 3000)"
	case "smallint":
		return "(g % 30000)::smallint"
	case "boolean":
		return "(g %% 2 = 0)"
	case "int":
		return "(g %% 1000000)::int"
	case "jsonb":
		return "jsonb_build_object('k', g)"
	case "double precision":
		return "g::double precision / 3"
	}
	return "g"
}

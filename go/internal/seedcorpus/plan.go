package seedcorpus

// The plan: target -> the seeds it gets.
//
// The SELECTOR is the index into the harness's own variant table; see the
// corresponding *_fuzzer.c. A target with no selector consumes the input
// whole.

// OrioleDBStatements exercise the storage engine itself.
//
// The regress SQL never writes "USING orioledb", so without these the OrioleDB
// workspaces fuzz stock PostgreSQL with an unused extension loaded.
var OrioleDBStatements = []string{
	// DDL: the table access method itself, and the index types it implements.
	"CREATE EXTENSION IF NOT EXISTS orioledb;",
	"CREATE TABLE o_t (i int NOT NULL, t text, PRIMARY KEY (i)) USING orioledb;",
	"CREATE TABLE o_w (i int NOT NULL, j int, t text, PRIMARY KEY (i)) USING orioledb;",
	"CREATE TABLE o_c (i int NOT NULL, v numeric, PRIMARY KEY (i)) USING orioledb WITH (compress = 1);",
	"CREATE TABLE o_noPK (i int, t text) USING orioledb;",
	"CREATE INDEX o_t_t_idx ON o_t (t);",
	"CREATE UNIQUE INDEX o_w_j_idx ON o_w (j);",
	"ALTER TABLE o_t ADD COLUMN extra jsonb;",
	"ALTER TABLE o_t DROP COLUMN t;",
	"ALTER TABLE o_t ALTER COLUMN i TYPE bigint;",
	"DROP TABLE o_t;",
	// DML: the paths through the B-tree, the undo log and the tuple format.
	"INSERT INTO o_t SELECT g, 'row ' || g FROM generate_series(1, 1000) g;",
	"INSERT INTO o_t VALUES (1, 'x') ON CONFLICT (i) DO UPDATE SET t = excluded.t;",
	"UPDATE o_t SET t = repeat('x', 10000) WHERE i % 7 = 0;",
	"DELETE FROM o_t WHERE i % 3 = 0;",
	"SELECT count(*) FROM o_t;",
	"SELECT * FROM o_t WHERE i BETWEEN 10 AND 200 ORDER BY i DESC;",
	"SELECT * FROM o_t JOIN o_w USING (i);",
	"MERGE INTO o_t USING o_w ON o_t.i = o_w.i WHEN MATCHED THEN UPDATE SET t = o_w.t WHEN NOT MATCHED THEN INSERT VALUES (o_w.i, o_w.t);",
	// Transactions and undo.
	"BEGIN; INSERT INTO o_t VALUES (-1, 'a'); ROLLBACK;",
	"BEGIN; UPDATE o_t SET t = 'b'; SAVEPOINT s1; DELETE FROM o_t; ROLLBACK TO s1; COMMIT;",
	"BEGIN ISOLATION LEVEL REPEATABLE READ; SELECT * FROM o_t LIMIT 5; COMMIT;",
	// Maintenance: checkpoints, vacuum and the on-disk structures they rewrite.
	"CHECKPOINT;",
	"VACUUM o_t;",
	"VACUUM FULL o_t;",
	"ANALYZE o_t;",
	"TRUNCATE o_t;",
	"REINDEX TABLE o_t;",
	// OrioleDB's own introspection, which walks the packed page structures.
	"SELECT orioledb_tbl_structure('o_t'::regclass);",
	"SELECT orioledb_table_description('o_t'::regclass);",
	"SELECT orioledb_tbl_check('o_t'::regclass);",
	"SELECT * FROM orioledb_table_pages('o_t'::regclass);",
	"SELECT orioledb_get_table_descrs();",
	"SELECT orioledb_commit_hash();",
}

// sel prepends a selector byte to each value.
func sel(b byte, vals []string) [][]byte {
	out := make([][]byte, 0, len(vals))
	for _, v := range vals {
		out = append(out, append([]byte{b}, []byte(v)...))
	}
	return out
}

// plain uses the value as-is, for the targets that consume no selector.
func plain(vals []string) [][]byte {
	out := make([][]byte, 0, len(vals))
	for _, v := range vals {
		out = append(out, []byte(v))
	}
	return out
}

// BuildPlan assembles every target's seeds from the regress tree.
func BuildPlan(sqldir string) map[string][][]byte {
	stmts := SQLStatements(sqldir)
	lit := func(files ...string) []string { return Literals(sqldir, files) }

	plan := map[string][][]byte{
		// SQL statements: no selector for the query targets (they take the
		// statement whole), selector 0 == RAW_PARSE_DEFAULT for raw_parser.
		"simple_query_fuzzer": plain(stmts),
		"spi_query_fuzzer":    plain(stmts),
		"raw_parser_fuzzer":   sel(0, stmts),

		"json_parser_fuzzer": plain(lit("json.sql", "jsonb.sql", "json_encoding.sql")),
		"jsonpath_fuzzer":    sel(0, lit("jsonpath.sql", "jsonb_jsonpath.sql", "sqljson_queryfuncs.sql")),
		"numeric_fuzzer":     sel(0, lit("numeric.sql", "numeric_big.sql", "numerology.sql")),
		"regex_fuzzer":       sel(0, lit("regex.sql", "strings.sql", "text.sql")),

		// Config-file targets get a synthesized starting point: the real
		// samples are elsewhere in the tree and mostly comments.
		"config_file_fuzzer": {
			[]byte("shared_buffers = 128MB\nwork_mem = '4MB'\nlog_line_prefix = '%m [%p] '\n"),
			[]byte("include 'other.conf'\ninclude_if_exists 'maybe.conf'\n"),
			[]byte("max_connections=100\n#comment\nfsync = off\n"),
			[]byte("search_path = \"$user\", public\n"),
		},
		"hba_file_fuzzer": {
			[]byte("\x00local all all trust\n"),
			[]byte("\x00host all all 127.0.0.1/32 scram-sha-256\n"),
			[]byte("\x00hostssl replication repl 0.0.0.0/0 cert clientcert=verify-full\n"),
			[]byte("\x00host all all ::1/128 ldap ldapserver=example.com ldapport=389\n"),
			[]byte("\x00include_if_exists other_hba.conf\n"),
			[]byte("\x01mymap /^(.*)@example\\.com$ \\1\n"),
		},
		"conninfo_fuzzer": {
			[]byte("host=localhost port=5432 dbname=postgres user=me"),
			[]byte("postgresql://user:secret@localhost:5432/db?sslmode=require"),
			[]byte("postgres://%2Fvar%2Flib%2Fpostgresql/db"),
			[]byte("postgresql://host1:123,host2:456/db?target_session_attrs=any"),
			[]byte(`dbname='quoted \'value\'' options='-c geqo=off'`),
		},
		"xlogreader_fuzzer": {
			// SizeOfXLogRecord is 24 bytes: tot_len, xid, prev, info, rmid, crc
			make([]byte, 24),
			append([]byte{0x18, 0, 0, 0}, make([]byte, 20)...),
			append(append([]byte{0x30, 0, 0, 0}, make([]byte, 20)...), 0x00, 0x10, 0x00, 0x00),
		},
		"protocol_fuzzer": {
			[]byte("Q\x00\x00\x00\x0dSELECT 1\x00"),
			[]byte("P\x00\x00\x00\x10\x00SELECT $1\x00\x00\x00"),
			[]byte("X\x00\x00\x00\x04"),
		},
	}

	// Several selectors over the same values: the harness reads the first byte
	// to choose the variant, so one literal seeds every parse mode.
	for _, s := range []byte{0, 1, 2, 3} {
		plan["jsonb_fuzzer"] = append(plan["jsonb_fuzzer"], sel(s, lit("json.sql", "jsonb.sql"))...)
		plan["tsearch_fuzzer"] = append(plan["tsearch_fuzzer"],
			sel(s, lit("tstypes.sql", "tsearch.sql", "tsdicts.sql"))...)
	}
	for _, s := range []byte{0, 1, 2} {
		plan["formatting_fuzzer"] = append(plan["formatting_fuzzer"],
			sel(s, lit("horology.sql", "numeric.sql"))...)
	}

	for _, p := range []struct {
		Sel   byte
		Files []string
	}{
		{0, []string{"date.sql"}}, {1, []string{"time.sql"}},
		{2, []string{"timetz.sql"}}, {3, []string{"timestamp.sql"}},
		{4, []string{"timestamptz.sql"}}, {5, []string{"interval.sql"}},
	} {
		plan["datetime_fuzzer"] = append(plan["datetime_fuzzer"], sel(p.Sel, lit(p.Files...))...)
	}

	for _, p := range []struct {
		Sel  byte
		File string
	}{
		{0, "point.sql"}, {1, "lseg.sql"}, {2, "line.sql"}, {3, "box.sql"},
		{4, "path.sql"}, {5, "polygon.sql"}, {6, "circle.sql"},
	} {
		plan["geo_fuzzer"] = append(plan["geo_fuzzer"],
			sel(p.Sel, lit(p.File, "geometry.sql", "create_misc.sql"))...)
	}

	for _, p := range []struct {
		Sel  byte
		File string
	}{{0, "inet.sql"}, {1, "inet.sql"}, {2, "macaddr.sql"}, {3, "macaddr8.sql"}} {
		plan["network_fuzzer"] = append(plan["network_fuzzer"], sel(p.Sel, lit(p.File))...)
	}

	for _, p := range []struct {
		Sel  byte
		File string
	}{
		{0, "boolean.sql"}, {1, "int2.sql"}, {2, "int4.sql"}, {3, "int8.sql"},
		{4, "float4.sql"}, {5, "float8.sql"}, {6, "oid.sql"},
		{12, "strings.sql"}, {13, "text.sql"}, {16, "uuid.sql"},
		{17, "money.sql"}, {23, "bit.sql"}, {24, "bit.sql"},
	} {
		plan["scalar_types_fuzzer"] = append(plan["scalar_types_fuzzer"], sel(p.Sel, lit(p.File))...)
	}

	for _, p := range []struct {
		Sel  byte
		File string
	}{
		{0, "arrays.sql"}, {3, "arrays.sql"}, {10, "rangetypes.sql"},
		{14, "multirangetypes.sql"}, {16, "privileges.sql"},
	} {
		plan["backend_types_fuzzer"] = append(plan["backend_types_fuzzer"], sel(p.Sel, lit(p.File))...)
	}

	// Encoding ids that matter most: UTF8 (6), plus the single-byte and the
	// tricky multibyte ones. Capped at 200 values per encoding -- eight
	// selectors over the whole of strings.sql would be most of the corpus.
	encVals := lit("conversion.sql", "unicode.sql", "strings.sql")
	if len(encVals) > 200 {
		encVals = encVals[:200]
	}
	for _, e := range []byte{0, 6, 7, 8, 9, 10, 11, 12} {
		plan["encoding_fuzzer"] = append(plan["encoding_fuzzer"], sel(e, encVals)...)
	}

	// Binary targets: no useful text seeds, but something structurally
	// plausible to mutate from.
	for s := 0; s < 50; s += 7 {
		for _, payload := range [][]byte{
			{0, 0, 0, 1}, make([]byte, 8),
			{0, 0, 0, 4, 0, 0, 0, 1},
			{255, 255, 255, 255, 255, 255, 255, 255,
				255, 255, 255, 255, 255, 255, 255, 255},
		} {
			plan["binary_recv_fuzzer"] = append(plan["binary_recv_fuzzer"],
				append([]byte{byte(s)}, payload...))
		}
	}
	return plan
}

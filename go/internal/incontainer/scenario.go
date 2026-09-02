package incontainer

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"pgfuzz/internal/scenario"
)

// Scenario replays a recorded storage scenario, in Go.
//
// Usage: _scenario /scenario.json
//
// This replaces about 150 lines of shell that this program used to generate
// and hand to bash -c: quoting decided by string concatenation, no syntax
// check until it ran, and failures surfacing as a message from a script
// nobody could see. The logic is the same; it is now in a language with
// types and a compiler.
func Scenario(argv []string) int {
	if len(argv) < 1 {
		fmt.Fprintln(os.Stderr, "_scenario: <scenario.json>")
		return 2
	}
	raw, err := os.ReadFile(argv[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "SFZ-SETUP-FAILED: %v\n", err)
		return 3
	}
	rec, err := scenario.UnmarshalStrict(raw)
	if err != nil {
		fmt.Fprintf(os.Stderr, "SFZ-SETUP-FAILED: %v\n", err)
		return 3
	}
	sc := rec.Scenario

	work, err := os.MkdirTemp("/tmp", "sfz.")
	if err != nil {
		fmt.Printf("SFZ-SETUP-FAILED: %v\n", err)
		return 3
	}
	for _, d := range []string{"ts_a", "ts_b"} {
		os.MkdirAll(filepath.Join(work, d), 0o700)
	}
	srv := &Server{
		Data: filepath.Join(work, "data"),
		Sock: "/tmp",
		Log:  filepath.Join(work, "server.log"),
	}
	if sc.OrioleDB {
		// OrioleDB is a table access method as well as an extension: without
		// the preload, CREATE TABLE ... USING orioledb fails on an unknown
		// access method.
		srv.Preload = "orioledb"
	}
	fail := func(what string) int {
		fmt.Printf("SFZ-RESULT: %s\n", what)
		fmt.Println("SFZ-BEGIN-LOG")
		fmt.Println(srv.Tail(40))
		srv.Stop()
		return 1
	}

	if err := srv.Init("/out"); err != nil {
		fmt.Printf("SFZ-SETUP-FAILED: %v\n", err)
		return 3
	}
	if err := srv.Start("/out"); err != nil {
		fmt.Printf("SFZ-SETUP-FAILED: %v\n%s\n", err, srv.Tail(30))
		return 3
	}
	db := "dbfuzz"
	if out, err := srv.SQL("/out", "postgres", []string{"CREATE DATABASE dbfuzz;"}); err != nil &&
		!strings.Contains(out, "already exists") {
		db = "postgres"
	}
	if sc.OrioleDB {
		if out, err := srv.SQL("/out", db, []string{"CREATE EXTENSION IF NOT EXISTS orioledb;"}); err != nil {
			fmt.Printf("SFZ-SETUP-FAILED: orioledb extension: %s\n", firstLines(out, 3))
			return 3
		}
	}

	// ---- setup -------------------------------------------------------
	setup := scenario.RenderSetup(sc)
	// The tablespace directories only exist here, so the paths are filled in
	// now. The SQL leaves RenderSetup exactly as the goldens check it.
	setup = strings.Replace(setup, "CREATE TABLESPACE ts_a LOCATION ''",
		"CREATE TABLESPACE ts_a LOCATION '"+filepath.Join(work, "ts_a")+"'", 1)
	setup = strings.Replace(setup, "CREATE TABLESPACE ts_b LOCATION ''",
		"CREATE TABLESPACE ts_b LOCATION '"+filepath.Join(work, "ts_b")+"'", 1)
	setupPath := filepath.Join(work, "setup.sql")
	os.WriteFile(setupPath, []byte(setup), 0o644)

	fmt.Println("SFZ-PHASE: setup")
	if out, err := srv.File("/out", db, setupPath, true); err != nil {
		// A scenario that could not be BUILT has not reproduced anything, and
		// its own result word keeps that from reading as a finding.
		fmt.Printf("SFZ-RESULT: setup-failed: %s\n", pickError(out))
		fmt.Println("SFZ-BEGIN-LOG")
		fmt.Println(srv.Tail(30))
		srv.Stop()
		return 3
	}

	// Expected counts come from what the load ACTUALLY produced: ON CONFLICT
	// and partition routing can legitimately land fewer than `rows`.
	expect := map[string]string{}
	for _, t := range sc.Tables {
		if out, err := srv.SQL("/out", db, []string{"SELECT count(*) FROM " + t.Name + ";"}); err == nil {
			expect[t.Name] = strings.TrimSpace(out)
		}
	}
	if what := probe(srv, db, sc, expect, "after_load", ""); what != "" {
		return fail(what)
	}

	// ---- steps -------------------------------------------------------
	for _, st := range sc.Steps {
		p, ok := scenario.PlanStep(st, sc)
		if !ok {
			fmt.Printf("SFZ-SKIP: unplanned op %s\n", st.Op)
			continue
		}
		fmt.Printf("SFZ-STEP: %s:%s\n", st.Op, st.Table)
		switch p.Kind {
		case scenario.SQL:
			if out, err := srv.SQL("/out", db, p.SQL); err != nil {
				return fail(st.Op + ": " + pickError(out))
			}
		case scenario.Concurrent:
			done := make(chan struct{})
			go func(stmts []string) { srv.SQL("/out", db, stmts); close(done) }(p.SQL)
			srv.SQL("/out", db, []string{"SELECT pg_sleep(0.2);"})
			<-done
		case scenario.Control:
			if p.Ctl == "crash" {
				srv.Crash()
			} else {
				srv.Stop()
			}
			if err := srv.Start("/out"); err != nil {
				return fail(st.Op + ": server did not come back: " + err.Error())
			}
		}
		switch {
		case p.RowDelta != 0 && st.Table != "":
			// A KNOWN delta is predicted, never adopted. These are the steps
			// whose whole purpose is that the count lands on a number we can
			// state in advance; asking the server what it thinks would make
			// the oracle agree with any answer it gave.
			if n, err := strconv.Atoi(strings.TrimSpace(expect[st.Table])); err == nil {
				expect[st.Table] = strconv.Itoa(n + p.RowDelta)
			}
		case p.ChangesRows && st.Table != "":
			// This step is SUPPOSED to move the count by an amount we do not
			// model, so adopt the new one. Comparing against the load forever
			// made insert_more and delete_half "fail" every scenario they
			// appeared in.
			if out, err := srv.SQL("/out", db, []string{"SELECT count(*) FROM " + st.Table + ";"}); err == nil {
				expect[st.Table] = strings.TrimSpace(out)
			}
		}
		if what := probe(srv, db, sc, expect, "after_"+st.Op, st.Table); what != "" {
			return fail(what)
		}
	}

	fmt.Println("SFZ-RESULT: clean")
	srv.Stop()
	return 0
}

// probe runs the consistency checks and returns the first failure.
func probe(srv *Server, db string, sc scenario.Scenario, expect map[string]string, phase, stepTable string) string {
	tag := phase
	if stepTable != "" {
		tag = phase + ":" + stepTable
	}
	for _, t := range sc.Tables {
		label := tag + "/" + t.Name
		for _, p := range scenario.ProbesFor(t) {
			switch {
			case p.Want == "rows":
				out, err := srv.SQL("/out", db, []string{p.SQL + ";"})
				if err != nil {
					return label + ": count failed"
				}
				got := strings.TrimSpace(out)
				if want, ok := expect[t.Name]; ok && got != want {
					return fmt.Sprintf("%s: expected %s rows, got %s", label, want, got)
				}
			case p.Name == "access-paths":
				q := fmt.Sprintf("SELECT count(*) FROM %s WHERE v > 0;", t.Name)
				seq, _ := srv.SQL("/out", db, []string{
					"SET enable_indexscan=off;", "SET enable_bitmapscan=off;", q})
				idx, _ := srv.SQL("/out", db, []string{"SET enable_seqscan=off;", q})
				s, i := lastLine(seq), lastLine(idx)
				if s != i {
					// The only probe that catches a WRONG ANSWER rather than a
					// crash: the engine asked one question two ways.
					return fmt.Sprintf("%s: access paths disagree -- seqscan='%s' indexscan='%s' for [%s]",
						label, s, i, strings.TrimSuffix(q, ";"))
				}
			default:
				if out, err := srv.SQL("/out", db, []string{p.SQL + ";"}); err != nil {
					if p.Name == "orioledb_tbl_check" {
						return label + ": orioledb_tbl_check: " + pickError(out)
					}
					return label + ": probe failed: " + strings.TrimSuffix(p.SQL, ";")
				}
			}
		}
	}
	return ""
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	return strings.TrimSpace(lines[len(lines)-1])
}

// pickError finds the line worth reporting.
func pickError(out string) string {
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, "ERROR:") || strings.Contains(l, "FATAL:") ||
			strings.Contains(l, "server closed the connection") {
			return strings.TrimSpace(l)
		}
	}
	return firstLines(out, 1)
}

// SQLOnly runs one .sql file against a server and reports what happened.
//
// Usage: _sql /sql
func SQLOnly(argv []string) int {
	path := "/sql"
	if len(argv) > 0 {
		path = argv[0]
	}
	work, err := os.MkdirTemp("/tmp", "pgs.")
	if err != nil {
		fmt.Printf("PGFUZZ-SETUP-FAILED: %v\n", err)
		return 3
	}
	srv := &Server{
		Data: filepath.Join(work, "data"),
		Sock: "/tmp",
		Log:  filepath.Join(work, "server.log"),
	}
	if Exists(filepath.Join(PGLib("/out"), "orioledb.so")) {
		srv.Preload = "orioledb"
	}
	if err := srv.Init("/out"); err != nil {
		fmt.Printf("PGFUZZ-SETUP-FAILED: %v\n", err)
		return 3
	}
	if err := srv.Start("/out"); err != nil {
		fmt.Printf("PGFUZZ-SETUP-FAILED: %v\n%s\n", err, srv.Tail(30))
		return 3
	}
	db := "dbfuzz"
	if out, err := srv.SQL("/out", "postgres", []string{"CREATE DATABASE dbfuzz;"}); err != nil &&
		!strings.Contains(out, "already exists") {
		db = "postgres"
	}
	// Which database, and how psql exited: neither decides the verdict, but a
	// human reading the output needs to know whether the statements ran in
	// dbfuzz or fell back to postgres.
	fmt.Printf("PGFUZZ-DB:%s\n", db)
	fmt.Println("PGFUZZ-BEGIN-SQL")
	out, err := srv.File("/out", db, path, false)
	fmt.Print(out)
	fmt.Printf("PGFUZZ-PSQL-EXIT:%d\n", exitCode(err))
	if srv.Ready("/out") {
		fmt.Println("PGFUZZ-SERVER:alive")
	} else {
		fmt.Println("PGFUZZ-SERVER:dead")
	}
	fmt.Println("PGFUZZ-BEGIN-LOG")
	fmt.Println(srv.Tail(60))
	srv.Stop()
	return 0
}

var _ = json.Marshal

// exitCode turns a wait error back into a status, so the marker means what the
// shell's $? meant.
func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	return -1
}

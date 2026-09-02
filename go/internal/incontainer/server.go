package incontainer

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Server is a postmaster this process owns.
//
// Owned, not talked to: crash and recovery are a kill and a start when the
// postmaster is a child process. A driver outside the container would have to
// reconnect across a crash it caused, through docker, and tell "restarting"
// from "gone" -- which is the exact distinction these findings turn on.
type Server struct {
	Data    string
	Sock    string
	Log     string
	Preload string
	cmd     *exec.Cmd

	// The superuser to connect as, or "" for the OS user.
	//
	// Not a constant, because the two Init paths do not agree on it. A fresh
	// initdb is ours to name, so it gets "pgfuzz"; the build's PREPARED data
	// directory was created by build.sh under whatever user ran it, and
	// connecting to that as "pgfuzz" fails with `role "pgfuzz" does not
	// exist` -- before a single statement of the scenario runs, which then
	// reads as "could not run" for every finding in an oriole workspace.
	user string
}

// uarg supplies -U only when we know the name. libpq defaults to the OS user,
// which is what the prepared directory was initdb'd under.
func (s *Server) uarg() []string {
	if s.user == "" {
		return nil
	}
	return []string{"-U", s.user}
}

// Init creates a data directory, or copies the build's prepared one.
//
// The prepared one when it exists: build.sh already ran initdb and created
// every extension the workspace declares, and a fresh initdb means CREATE
// EXTENSION mchar -- which fails, because the plugin .so is ASan-built while
// tmp_install's postgres is plain. Copied, never used in place: /out is the
// workspace's own build and a server writing into it changes what every later
// run measures.
func (s *Server) Init(out string) error {
	if err := os.MkdirAll(s.Data, 0o700); err != nil {
		return err
	}
	prepared := filepath.Join(out, "data")
	if Exists(filepath.Join(prepared, "PG_VERSION")) {
		if o, err := Run("cp", "-a", prepared+"/.", s.Data+"/"); err != nil {
			return fmt.Errorf("copying prepared data dir: %w: %s", err, o)
		}
		os.Chmod(s.Data, 0o700)
		os.Remove(filepath.Join(s.Data, "postmaster.pid"))
		s.user = "" // build.sh named the superuser; libpq's default matches it
		return nil
	}
	o, err := Run(filepath.Join(PGBin(out), "initdb"),
		"-D", s.Data, "-U", "pgfuzz", "--no-sync", "-A", "trust")
	if err != nil {
		return fmt.Errorf("initdb: %w: %s", err, firstLines(o, 5))
	}
	s.user = "pgfuzz"
	return nil
}

// Start launches the postmaster.
//
// restart_after_crash=off is the setting the whole exercise depends on. With
// the default, a backend abort makes the postmaster reinitialise within
// seconds, so a liveness check a moment later SUCCEEDS -- and every
// cluster-fatal finding reads as a clean run.
func (s *Server) Start(out string) error {
	args := []string{"-D", s.Data, "-k", s.Sock, "-c", "listen_addresses=",
		"-c", "restart_after_crash=off"}
	if s.Preload != "" {
		// On the command line, not in postgresql.conf: the prepared data
		// directory ships a postgresql.auto.conf, which PostgreSQL reads last
		// and which overrode the appended setting.
		args = append(args, "-c", "shared_preload_libraries="+s.Preload)
	}
	lf, err := os.OpenFile(s.Log, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	cmd := exec.Command(filepath.Join(PGBin(out), "postgres"), args...)
	cmd.Stdout, cmd.Stderr = lf, lf
	cmd.Env = append(os.Environ(), "LD_LIBRARY_PATH="+PGLib(out))
	if err := cmd.Start(); err != nil {
		lf.Close()
		return err
	}
	s.cmd = cmd
	if !WaitReady(func() bool { return s.Ready(out) }, 500*time.Millisecond, 30*time.Second) {
		return fmt.Errorf("server never became ready")
	}
	return nil
}

// Ready asks the SERVER, not the process table: a postmaster that is up but
// not accepting connections is not a working server.
func (s *Server) Ready(out string) bool {
	args := append([]string{"-h", s.Sock}, s.uarg()...)
	args = append(args, "-d", "postgres", "-q")
	c := exec.Command(filepath.Join(PGBin(out), "pg_isready"), args...)
	c.Env = append(os.Environ(), "LD_LIBRARY_PATH="+PGLib(out))
	return c.Run() == nil
}

// Crash kills the postmaster outright, so recovery has to replay WAL.
func (s *Server) Crash() {
	if s.cmd != nil && s.cmd.Process != nil {
		s.cmd.Process.Kill()
		s.cmd.Wait()
	}
}

// Stop ends it cleanly.
func (s *Server) Stop() {
	if s.cmd != nil && s.cmd.Process != nil {
		s.cmd.Process.Signal(os.Interrupt)
		done := make(chan struct{})
		go func() { s.cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			s.cmd.Process.Kill()
		}
	}
}

// SQL runs statements as ONE session and returns the output.
//
// One session matters: BEGIN, the work and ROLLBACK in three separate psql
// invocations are three separate backends, and every transactional shape --
// savepoints, 2PC, isolation levels -- then exercises nothing.
func (s *Server) SQL(out, db string, stmts []string) (string, error) {
	args := append([]string{"-h", s.Sock}, s.uarg()...)
	args = append(args, "-d", db, "-v", "ON_ERROR_STOP=1", "-Atq")
	c := exec.Command(filepath.Join(PGBin(out), "psql"), args...)
	c.Stdin = strings.NewReader(strings.Join(stmts, "\n") + "\n")
	c.Env = append(os.Environ(), "LD_LIBRARY_PATH="+PGLib(out))
	res, err := c.CombinedOutput()
	return string(res), err
}

// File runs a .sql file, not stopping at the first error.
func (s *Server) File(out, db, path string, stopOnError bool) (string, error) {
	stop := "ON_ERROR_STOP=0"
	if stopOnError {
		stop = "ON_ERROR_STOP=1"
	}
	args := append([]string{"-h", s.Sock}, s.uarg()...)
	args = append(args, "-d", db, "-v", stop, "-f", path)
	c := exec.Command(filepath.Join(PGBin(out), "psql"), args...)
	c.Env = append(os.Environ(), "LD_LIBRARY_PATH="+PGLib(out))
	res, err := c.CombinedOutput()
	return string(res), err
}

// Tail returns the end of the server log.
//
// Returned WITH a failure rather than after it: a driver that exits at the
// first fault and dumps the log at the end never dumps it, which turns "the
// server died" into a report with no site in it -- and the site is the only
// part a maintainer can act on.
func (s *Server) Tail(n int) string {
	b, err := os.ReadFile(s.Log)
	if err != nil {
		return ""
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

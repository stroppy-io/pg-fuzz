// Package pgserver runs SQL against a postmaster built by a workspace, and
// reports what the server did about it.
//
// WHY THIS IS A SEPARATE VEHICLE
// ==============================
// A fuzz target takes bytes. A large share of the findings here do not: the
// VACUUM/SPI context leak, the time-zone cache growth and the mchar corruption
// are all "run this SQL against a server and watch". Until now the only way to
// do that was mchar's hand-built compose bundle -- carved out for one finding,
// 163 MB of packed tree, not reusable. A fuzz build already ships tmp_install,
// so any workspace can be a server and nothing needs packing.
//
// THE ONE SETTING THAT DECIDES WHETHER THIS WORKS
// ===============================================
// restart_after_crash=off. With the default, a backend abort makes the
// postmaster reinitialise within seconds, so a liveness check a moment later
// SUCCEEDS -- which reads as "the server survived" when what happened is a
// forced restart that killed every session. mchar's Dockerfile learned that
// and says so; the same trap would silently turn every cluster-fatal finding
// here into a clean run.
//
// WHAT IT DOES NOT DECIDE
// =======================
// Whether the outcome IS the defect. A leak finding wants a growing context, a
// wrong-answer finding wants a row count. This reports what happened to the
// server and hands back the output; judging it is the caller's job.
package pgserver

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Outcome is what the server did.
type Outcome int

const (
	Failed     Outcome = iota // could not get a server up at all
	ServerDied                // the postmaster is gone: cluster-fatal
	Errored                   // SQL raised an error, server still serving
	Survived                  // ran, server still serving
)

func (o Outcome) String() string {
	switch o {
	case ServerDied:
		return "SERVER DIED"
	case Errored:
		return "sql error, server alive"
	case Survived:
		return "survived"
	default:
		return "FAILED TO RUN"
	}
}

// Result carries the outcome and the evidence for it.
type Result struct {
	Outcome Outcome
	Marker  string // the interesting log or client line, when there is one
	Elapsed time.Duration
	Output  string
}

// Request is one SQL reproduction.
type Request struct {
	Image    string // the workspace's builder image; it has the runtime libs
	Out      string // the build output, bind-mounted at /out
	SQL      string // path to a .sql file on the host
	Scenario string // path to a scenario .json, run instead of the SQL
	Timeout  time.Duration
	Stream   io.Writer
}

// Lines that mean the server did something worth reporting, most specific
// first, so the marker names the mechanism rather than the symptom.
var markers = []*regexp.Regexp{
	regexp.MustCompile(`(?m)^.*detected write past chunk end.*$`),
	regexp.MustCompile(`(?m)^.*pfree called with invalid pointer.*$`),
	regexp.MustCompile(`(?m)^TRAP: failed Assert\(.*$`),
	regexp.MustCompile(`(?m)^.*terminating connection because of crash of another server process.*$`),
	regexp.MustCompile(`(?m)^PANIC:.*$`),
	regexp.MustCompile(`(?m)^.*server closed the connection unexpectedly.*$`),
	regexp.MustCompile(`(?m)^==\d+==ERROR: \w+Sanitizer: .*$`),
}

// The container runs THIS BINARY, bind-mounted at /pgfuzz and re-executed with
// a hidden subcommand -- see internal/incontainer. Nothing is shipped
// alongside it and nothing is generated for a shell to interpret.
//
// initdb runs every time, into a fresh directory: a data directory carried
// between runs is state, and state makes two runs of the same input two
// different experiments.

// Run starts a server, runs the SQL, and reports what happened.
func Run(ctx context.Context, r Request) (Result, error) {
	self, err := os.Executable()
	if err != nil {
		return Result{Outcome: Failed}, err
	}
	if real, err := filepath.EvalSymlinks(self); err == nil {
		self = real
	}

	// A caller supplying a scenario needs no .sql file.
	abs := ""
	if r.Scenario == "" {
		var err error
		abs, err = absExisting(r.SQL)
		if err != nil {
			return Result{Outcome: Failed}, err
		}
	}
	if r.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, r.Timeout)
		defer cancel()
	}

	args := []string{
		"run", "--privileged", "--shm-size=2g", "--platform", "linux/amd64", "--rm",
		"-v", r.Out + ":/out",
	}
	args = append(args, "-v", self+":/pgfuzz:ro")
	if abs != "" {
		args = append(args, "-v", abs+":/sql:ro")
	}
	if r.Scenario != "" {
		args = append(args, "-v", r.Scenario+":/scenario.json:ro")
	}
	// THE PLAIN LIBRARIES, MOUNTED OVER THE INSTRUMENTED ONES.
	//
	// An ASan .so cannot load into a plain postgres, and tmp_install's postgres
	// IS plain -- build.sh compiles twice, uninstrumented for initdb and
	// instrumented for the targets. The build ships x.so.plain beside each
	// x.so for exactly this, and mchar's pack.sh copies them over.
	//
	// Copying is not available here: /out is the workspace's own build
	// directory and a reproduction must not modify what every later run
	// measures. `$libdir` is compiled in, so redirecting the search path does
	// not help either -- the extension resolves an absolute path. Mounting
	// each plain file over its instrumented twin, read-only, changes what the
	// container sees and leaves the host untouched.
	args = append(args, plainMounts(r.Out)...)
	args = append(args,
		// initdb refuses to run as root, and the builder image runs as root.
		// uid 1000 exists in the ubuntu base and can read the bind-mounted
		// /out; everything it writes goes to /tmp inside the container.
		"--user", "1000:1000",
		"-e", "HOME=/tmp",
		"--entrypoint", "/pgfuzz",
	)
	args = append(args, r.Image)
	args = append(args, entry(r.Scenario)...)

	var buf bytes.Buffer
	var sink io.Writer = &buf
	if r.Stream != nil {
		sink = io.MultiWriter(&buf, r.Stream)
	}
	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Stdout, cmd.Stderr = sink, sink

	start := time.Now()
	_ = cmd.Run() // the payload's markers decide the verdict, not its exit code
	res := Result{Elapsed: time.Since(start), Output: buf.String()}

	if strings.Contains(res.Output, "PGFUZZ-SETUP-FAILED") {
		res.Outcome = Failed
		for _, l := range strings.Split(res.Output, "\n") {
			if strings.Contains(l, "PGFUZZ-SETUP-FAILED") {
				return res, fmt.Errorf("%s", strings.TrimSpace(l))
			}
		}
		return res, fmt.Errorf("could not start a server")
	}

	for _, re := range markers {
		if m := re.FindString(res.Output); m != "" {
			res.Marker = strings.TrimSpace(m)
			break
		}
	}

	switch {
	case strings.Contains(res.Output, "PGFUZZ-SERVER:dead"):
		res.Outcome = ServerDied
	case strings.Contains(res.Output, "PGFUZZ-SERVER:alive"):
		res.Outcome = Survived
		// An error the server handled is not a crash, and distinguishing them
		// keeps "the statement was rejected" from reading as "nothing
		// happened" -- which for several findings here is the whole point.
		if strings.Contains(res.Output, "\nERROR:") || strings.Contains(res.Output, "\nFATAL:") {
			res.Outcome = Errored
		}
	default:
		res.Outcome = Failed
		return res, fmt.Errorf("the run reported no server state")
	}
	return res, nil
}

func absExisting(p string) (string, error) {
	st, err := os.Stat(p)
	if err != nil {
		return "", fmt.Errorf("no such sql file: %s", p)
	}
	if st.IsDir() {
		return "", fmt.Errorf("not a file: %s", p)
	}
	return p, nil
}

// plainMounts returns -v arguments putting every x.so.plain over its x.so.
func plainMounts(out string) []string {
	lib := filepath.Join(out, "tmp_install", "usr", "local", "pgsql", "lib")
	hits, err := filepath.Glob(filepath.Join(lib, "*.so.plain"))
	if err != nil {
		return nil
	}
	var args []string
	for _, p := range hits {
		target := strings.TrimSuffix(p, ".plain")
		// Only over one that exists: mounting onto a missing path makes docker
		// create a directory there, and a directory named x.so fails to load
		// with a message that says nothing about why.
		if _, err := os.Stat(target); err != nil {
			continue
		}
		inside := filepath.Join("/out", "tmp_install", "usr", "local", "pgsql", "lib",
			filepath.Base(target))
		args = append(args, "-v", p+":"+inside+":ro")
	}
	return args
}

// entry picks which half of the binary the container runs.
func entry(scenarioPath string) []string {
	if scenarioPath != "" {
		return []string{"_scenario", "/scenario.json"}
	}
	return []string{"_sql", "/sql"}
}

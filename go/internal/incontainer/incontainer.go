// Package incontainer is the half of this tool that runs INSIDE a container.
//
// WHY THIS EXISTS AT ALL
// ======================
// Every container step used to be a shell script generated as a Go string and
// handed to `bash -c`: mount an overlay, start a postmaster, run psql, merge
// profiles. That is bash with none of bash's advantages -- no syntax checking,
// no types, quoting decided by string concatenation, and errors that surface
// as a message from a program nobody can see.
//
// The binary is static and CGO-free, so it runs in any Linux image. It is
// bind-mounted at /pgfuzz and re-executed with a hidden subcommand, and the
// work happens in the same language as everything else.
//
// WHAT IS STILL NOT OURS
// ======================
// `run_fuzzer` and `coverage` are OSS-Fuzz's own entry points, and llvm-cov,
// initdb and postgres are programs. Calling those is using an interface, not
// writing shell -- the distinction that matters is whether WE author the
// script, and after this we do not.
package incontainer

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

// MountOverlay puts a writable layer over a read-only build.
//
// Two concurrent runs otherwise share one /out and libFuzzer's artifact writes
// race; the coverage script wipes shared output directories at startup, so
// parallel runs destroyed each other's profile data. The overlay makes each
// run's writes private while the build underneath stays untouched.
func MountOverlay(lower, upper, work, target string) error {
	for _, d := range []string{upper, work, target} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
	}
	opts := fmt.Sprintf("lowerdir=%s,upperdir=%s,workdir=%s", lower, upper, work)
	if err := syscall.Mount("overlay", target, "overlay", 0, opts); err != nil {
		return fmt.Errorf("overlay mount: %w", err)
	}
	return nil
}

// Tee runs a command, copying its output to a file and to stdout.
//
// The FILE is the durable copy and stdout is the fragile one: a killed process
// loses whatever is buffered and one broken pipe loses everything, while a
// file on a bind mount survives both. libFuzzer deletes its own fuzz-<i>.log
// once it has printed them, so this is the only record that outlives a kill --
// and campaigns here are killed mid-slice routinely.
func Tee(logPath string, name string, args ...string) (int, error) {
	f, err := os.Create(logPath)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	cmd := exec.Command(name, args...)
	cmd.Stdout = multi(os.Stdout, f)
	cmd.Stderr = cmd.Stdout
	err = cmd.Run()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
		err = nil
	}
	return code, err
}

type multiWriter struct{ a, b *os.File }

func multi(a, b *os.File) *multiWriter { return &multiWriter{a, b} }

func (m *multiWriter) Write(p []byte) (int, error) {
	// The file first: if stdout is a broken pipe, the durable copy is already
	// written. The other order loses the line this call was made for.
	n, err := m.b.Write(p)
	m.a.Write(p)
	return n, err
}

// WaitReady polls until a check passes or the deadline expires.
//
// Polling a CHECK rather than sleeping a guess: a fixed sleep is either too
// short on a loaded box -- and this box is loaded, that is what it is for --
// or wasted time on an idle one.
func WaitReady(check func() bool, every, limit time.Duration) bool {
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		if check() {
			return true
		}
		time.Sleep(every)
	}
	return false
}

// Run executes a command, returning its combined output.
func Run(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	return string(out), err
}

// SelfPath is where the binary is mounted inside a container.
const SelfPath = "/pgfuzz"

// Exists reports whether a path is there.
func Exists(p string) bool { _, err := os.Stat(p); return err == nil }

// PGBin is the directory the built PostgreSQL programs live in.
func PGBin(out string) string {
	return filepath.Join(out, "tmp_install", "usr", "local", "pgsql", "bin")
}

// PGLib is the built PostgreSQL library directory.
func PGLib(out string) string {
	return filepath.Join(out, "tmp_install", "usr", "local", "pgsql", "lib")
}

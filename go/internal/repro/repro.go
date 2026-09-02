// Package repro runs one recorded input against one built target and says
// whether it still reproduces.
//
// WHY THIS IS NOT A CALL TO helper.py
// ===================================
// `pgfuzz repro` shells out to `infra/helper.py reproduce`, which is correct
// here and useless in a binary handed to somebody else: it needs the oss-fuzz
// clone AND a working python. This builds the same `docker run` directly, from
// the same fields, so the only runtime dependency is docker.
//
// WHY A VERDICT AND NOT AN EXIT CODE
// ==================================
// helper.py returns whatever the target returned. For triage the question is
// narrower and needs a word: did this input still crash the thing. A target
// that exits non-zero because the image is missing, or because the corpus path
// was wrong, is not "reproduced" -- and reading a setup failure as a
// reproduction is exactly the mistake that would put an unreproducible finding
// in front of a maintainer.
package repro

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Verdict is what happened.
type Verdict int

const (
	Error      Verdict = iota // could not run: no binary, no image, no docker
	Reproduced                // the target died, and the report names a site
	Clean                     // the target ran the input and survived
)

func (v Verdict) String() string {
	switch v {
	case Reproduced:
		return "REPRODUCED"
	case Clean:
		return "clean"
	default:
		return "ERROR"
	}
}

// Result carries the verdict and the evidence for it.
type Result struct {
	Verdict   Verdict
	Signature string // the crash line, when there is one
	Elapsed   time.Duration
	Output    string
}

// Request is one reproduction.
type Request struct {
	Image   string // gcr.io/oss-fuzz-base/base-runner:<base_os_version>
	Out     string // the project's build output, bind-mounted at /out
	Target  string
	Input   string
	Runs    int           // -runs=N; helper.py uses 100
	Timeout time.Duration // 0 means no deadline
	Stream  io.Writer     // if set, the container's output is copied here live
	Scratch string        // where the overlay's upper layer goes; defaults beside Out
}

// These are the lines that mean "the thing under test failed", in the order a
// report prints them. Kept as a list rather than one regexp so a new sanitizer
// is one line to add and so the matched text IS the signature.
var crashLines = []*regexp.Regexp{
	regexp.MustCompile(`(?m)^==\d+==ERROR: \w+Sanitizer: .*$`),
	regexp.MustCompile(`(?m)^SUMMARY: \w+Sanitizer: .*$`),
	regexp.MustCompile(`(?m)^.*runtime error: .*$`),
	regexp.MustCompile(`(?m)^TRAP: failed Assert\(.*$`),
	regexp.MustCompile(`(?m)^==\d+== ERROR: libFuzzer: .*$`),
}

// A container that could not start is not a clean run. These are docker's
// failures, not the target's, and they must never read as "did not reproduce".
var setupLines = []*regexp.Regexp{
	regexp.MustCompile(`(?mi)^.*(Unable to find image|no such file or directory|permission denied|Cannot connect to the Docker daemon).*$`),
}

// Run executes one input and judges the result.
func Run(ctx context.Context, r Request) (Result, error) {
	if r.Runs == 0 {
		r.Runs = 100
	}
	bin := filepath.Join(r.Out, r.Target)
	if _, err := os.Stat(bin); err != nil {
		return Result{Verdict: Error}, fmt.Errorf("target not built: %s", bin)
	}
	abs, err := filepath.Abs(r.Input)
	if err != nil {
		return Result{Verdict: Error}, err
	}
	if _, err := os.Stat(abs); err != nil {
		return Result{Verdict: Error}, fmt.Errorf("no such input: %s", abs)
	}

	if r.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, r.Timeout)
		defer cancel()
	}

	// The build is mounted as the LOWER layer of an overlay rather than
	// directly, because run_fuzzer mkdirs $OUT/<target>_<engine>_<san>_out
	// unconditionally and that lands root-owned inside the build otherwise.
	// See incontainer.Repro. The scratch holding the upper layer sits beside
	// the build so it is on the same filesystem -- overlayfs will not take a
	// tmpfs upperdir, which rules out the system temp directory.
	scratch := r.Scratch
	if scratch == "" {
		// Out is normally oss-fuzz/build/out/<project>, a SYMLINK into the
		// workspace. Resolve it first, or the scratch lands in the oss-fuzz
		// clone -- which is a checkout of someone else's repository and has no
		// business holding our per-run files.
		out := r.Out
		if real, err := filepath.EvalSymlinks(out); err == nil {
			out = real
		}
		scratch = filepath.Join(filepath.Dir(out), "reprotmp")
	}
	rundir, err := os.MkdirTemp(scratch, r.Target+"-")
	if err != nil {
		if err := os.MkdirAll(scratch, 0o755); err != nil {
			return Result{Verdict: Error}, err
		}
		if rundir, err = os.MkdirTemp(scratch, r.Target+"-"); err != nil {
			return Result{Verdict: Error}, err
		}
	}
	// The container removes the overlay layers itself, as root, which is the
	// only place the permissions are right: overlayfs's work directory is mode
	// 000 and root-owned, so this removal can only ever succeed on a directory
	// the container already emptied. If the container was killed before it got
	// there, say so rather than leaking silently -- `pgfuzz reown` is the way
	// back.
	defer func() {
		if err := os.RemoveAll(rundir); err != nil {
			fmt.Fprintf(os.Stderr, "repro: left scratch behind at %s: %v\n", rundir, err)
		}
	}()

	self, err := os.Executable()
	if err != nil {
		return Result{Verdict: Error}, err
	}
	if real, err := filepath.EvalSymlinks(self); err == nil {
		self = real
	}

	// Otherwise the same arguments infra/helper.py builds for `reproduce`, so
	// a result here and a result there are the same experiment.
	args := []string{
		"run", "--privileged", "--shm-size=2g", "--platform", "linux/amd64", "--rm",
		"-e", "HELPER=True", "-e", "ARCHITECTURE=x86_64",
		"-v", r.Out + ":/out-lower:ro",
		"-v", rundir + ":/run-ovl",
		"-v", abs + ":/testcase",
		// The binary mounts itself in and re-executes. It is static and
		// CGO-free, so it runs in any Linux image.
		"-v", self + ":/pgfuzz:ro",
		"--entrypoint", "/pgfuzz",
		"-t", r.Image,
		"_repro", r.Target, fmt.Sprintf("-runs=%d", r.Runs),
	}

	var buf bytes.Buffer
	var sink io.Writer = &buf
	if r.Stream != nil {
		sink = io.MultiWriter(&buf, r.Stream)
	}
	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Stdout = sink
	cmd.Stderr = sink

	start := time.Now()
	runErr := cmd.Run()
	res := Result{Elapsed: time.Since(start), Output: buf.String()}

	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		res.Verdict = Error
		return res, fmt.Errorf("timed out after %s", r.Timeout)
	}

	for _, re := range setupLines {
		if m := re.FindString(res.Output); m != "" {
			res.Verdict = Error
			return res, fmt.Errorf("could not run: %s", strings.TrimSpace(m))
		}
	}
	for _, re := range crashLines {
		if m := re.FindString(res.Output); m != "" {
			res.Verdict = Reproduced
			res.Signature = strings.TrimSpace(m)
			return res, nil
		}
	}

	// No crash text. A non-zero exit with nothing to show for it is still not a
	// reproduction -- it is a run nobody can characterise, and saying so is the
	// point of having three verdicts instead of two.
	if runErr != nil {
		res.Verdict = Error
		return res, fmt.Errorf("target exited non-zero with no sanitizer report: %w", runErr)
	}
	res.Verdict = Clean
	return res, nil
}

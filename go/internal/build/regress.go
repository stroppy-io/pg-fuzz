package build

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// "IT COMPILED" IS NOT EVIDENCE THAT A PATCH IS SOUND.
//
// The only check on a workspace patch is that it applied without leaving a
// .rej. That catches a patch which does not fit; it says nothing about whether
// the tree still behaves the way PostgreSQL's own tests say it should -- and a
// vendor patch that rewrites planner behaviour rewrites the expected output of
// dozens of core regression tests as a consequence. Twenty-seven of them in the
// case this was written for, all downstream of one feature, in exactly the code
// whose forward declarations had to be hand-merged to fit the minor version.
//
// DELIBERATELY NOT THE FUZZING BUILD. The targets are built with ASan, cassert
// and a harness diff that #ifdefs out main(), so `make check` could not drive
// that tree even in principle. This builds a plain PostgreSQL from the same
// patched export and runs the suite against it: what is under test is the
// PATCH, not the harness.
//
// --enable-cassert on purpose -- the assertions are most of the point of
// running these tests against a patched planner -- and no sanitizers, which
// are not what is under test and triple the runtime.

// RegressRequest is one patched tree to check.
type RegressRequest struct {
	// Src is the exported, already-patched PostgreSQL tree.
	Src string
	// Work is a scratch directory for the build and its logs.
	Work string
	// Image carries the toolchain. The project's own builder image has it.
	Image  string
	Stream io.Writer
}

// RegressResult is what the suite said.
type RegressResult struct {
	Passed int
	Failed int
	// FailedTests names them, because "3 of 215 tests failed" sends somebody
	// to a log to find out which.
	FailedTests []string
	CheckLog    string
	// Ran distinguishes "the suite failed" from "the suite never got to run",
	// which is the distinction every gate in this project turns on.
	Ran bool
}

const innerScript = `set -u
cd /work/src || exit 1
./configure --enable-cassert --without-icu --without-readline --without-zlib \
	> /work/configure.log 2>&1 || { echo "CONFIGURE FAILED"; tail -20 /work/configure.log; exit 1; }
make -j"$(nproc)" > /work/make.log 2>&1 || { echo "MAKE FAILED"; tail -40 /work/make.log; exit 1; }
echo "=== make check ==="
make check > /work/check.log 2>&1
echo "make check rc=$?"
tail -40 /work/check.log
`

// Regress builds a plain PostgreSQL from a patched tree and runs make check.
func Regress(ctx context.Context, r RegressRequest) (RegressResult, error) {
	var res RegressResult
	if err := os.MkdirAll(r.Work, 0o755); err != nil {
		return res, err
	}
	inner := filepath.Join(r.Work, "inner.sh")
	if err := os.WriteFile(inner, []byte(innerScript), 0o755); err != nil {
		return res, err
	}
	// The tree is bind-mounted where the script expects it. Copying rather
	// than mounting r.Src directly keeps the build out of the export every
	// other workspace shares.
	dst := filepath.Join(r.Work, "src")
	if _, err := os.Stat(dst); os.IsNotExist(err) {
		if err := copyTree(r.Src, dst); err != nil {
			return res, fmt.Errorf("staging the tree: %w", err)
		}
	}

	// AS THE HOST USER. initdb refuses to run as root and make check runs
	// initdb, so a container running as root cannot execute this suite at all.
	cmd := exec.CommandContext(ctx, "docker", "run", "--rm",
		"--user", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()),
		"-v", r.Work+":/work", "-w", "/work",
		r.Image, "bash", "/work/inner.sh")
	var sink io.Writer = io.Discard
	if r.Stream != nil {
		sink = r.Stream
	}
	cmd.Stdout, cmd.Stderr = sink, sink
	runErr := cmd.Run()

	res.CheckLog = filepath.Join(r.Work, "check.log")
	res.Passed, res.Failed, res.FailedTests, res.Ran = parseCheck(res.CheckLog)
	if !res.Ran {
		return res, fmt.Errorf("the suite did not run: %v (see %s/configure.log and %s/make.log)",
			runErr, r.Work, r.Work)
	}
	return res, nil
}

var (
	reAllPassed = regexp.MustCompile(`All (\d+) tests passed`)
	reSomeFail  = regexp.MustCompile(`(\d+) of (\d+) tests failed`)
	reNotOk     = regexp.MustCompile(`^not ok\s+\d+\s+[-+]?\s*(\S+)`)
)

// parseCheck reads pg_regress's own summary.
//
// RAN IS SEPARATE FROM PASSED. A configure or make failure leaves no check.log
// at all, and reporting that as "0 failures" would turn a tree that cannot even
// build into a passing one.
func parseCheck(path string) (passed, failed int, names []string, ran bool) {
	f, err := os.Open(path)
	if err != nil {
		return 0, 0, nil, false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if m := reAllPassed.FindStringSubmatch(line); m != nil {
			passed, _ = strconv.Atoi(m[1])
			ran = true
		}
		if m := reSomeFail.FindStringSubmatch(line); m != nil {
			failed, _ = strconv.Atoi(m[1])
			total, _ := strconv.Atoi(m[2])
			passed = total - failed
			ran = true
		}
		if m := reNotOk.FindStringSubmatch(strings.TrimSpace(line)); m != nil {
			names = append(names, m[1])
		}
	}
	return passed, failed, names, ran
}

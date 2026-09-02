// Package redgreen runs the red/green suite for the OSS-Fuzz postgresql
// harness defects.
//
// Each case is an assertion about UPSTREAM's harnesses that must FAIL before
// the corresponding fix and PASS after it.
//
// WHY THE SUITE EXISTS HERE AND NOT UPSTREAM
// ==========================================
// projects/postgresql/ ships no tests -- project.yaml is metadata and nothing
// else. The defects are therefore unfalsifiable in place: there is no way to
// say "this harness is broken" that upstream's CI can check, and no way to show
// a fix works other than by describing it. A patch series with a red/green pair
// per defect is a different kind of argument, and the cases are written against
// upstream's layout so they can be contributed as-is.
//
// WHY IT BUILDS WITH ASSERTIONS
// =============================
// project.yaml lists only the address sanitizer, so upstream builds without
// --enable-cassert, and that is exactly why these defects survived: without
// assertions a harness that hands the wrong structure to a function does not
// crash, it quietly does the wrong thing and keeps producing output that looks
// like work. Assertions are the oracle here, and turning them on periodically
// is itself one of the recommendations.
//
// It runs against a FRESH clone of google/oss-fuzz, never against the clones
// the fuzzing workspaces drive, and never against pg-fuzz/project/, which has
// diverged 2-3x from upstream and would prove nothing about upstream's files.
package redgreen

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Case is one row of cases.tsv.
type Case struct {
	ID     string
	Defect string
	Needs  string // the defect whose fix must be applied for this to be observable
	Target string
	Input  string // "-" for none
	Expect string
	Note   string
}

// Options says where everything lives and what to run.
type Options struct {
	Root   string // the pg-fuzz checkout: cases, inputs, preconditions, fixes
	Clone  string // a fresh google/oss-fuzz clone, built and modified
	Green  bool   // apply every fix; otherwise only the prerequisites
	Only   string // a single case id
	Out    io.Writer
	Docker string // base-runner image
}

const (
	project    = "postgresql"
	baseRunner = "gcr.io/oss-fuzz-base/base-runner:ubuntu-24-04"
)

// ReadCases parses cases.tsv.
func ReadCases(path string) ([]Case, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []Case
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		l := sc.Text()
		if strings.HasPrefix(l, "#") || strings.TrimSpace(l) == "" {
			continue
		}
		f := strings.Split(l, "\t")
		for len(f) < 7 {
			f = append(f, "")
		}
		out = append(out, Case{f[0], f[1], f[2], f[3], f[4], f[5], f[6]})
	}
	return out, sc.Err()
}

// Result counts what happened.
type Result struct{ Expected, Unexpected, Skipped int }

// Run drives the whole suite.
//
// One build per dependency group, not one per case: the build dominates the
// runtime, and cases whose `needs` column names a defect are only meaningful
// once that defect's fix is applied. Two builds at ~2 minutes each is a cheap
// price for cases that can actually discriminate.
func Run(ctx context.Context, o Options) (Result, error) {
	if o.Out == nil {
		o.Out = os.Stdout
	}
	if o.Docker == "" {
		o.Docker = baseRunner
	}
	cases, err := ReadCases(filepath.Join(o.Root, "tests/ossfuzz/cases.tsv"))
	if err != nil {
		return Result{}, err
	}
	if _, err := os.Stat(o.Clone); err != nil {
		return Result{}, fmt.Errorf("no clone at %s -- git clone https://github.com/google/oss-fuzz.git %s",
			o.Clone, o.Clone)
	}

	seen := map[string]bool{}
	var groups []string
	for _, c := range cases {
		if !seen[c.Needs] {
			seen[c.Needs] = true
			groups = append(groups, c.Needs)
		}
	}
	sort.Strings(groups)

	mode := "red"
	if o.Green {
		mode = "green"
	}
	out := filepath.Join(o.Clone, "build/out", project)

	var res Result
	for _, needs := range groups {
		if needs == "" {
			continue
		}
		if needs == "-" {
			fmt.Fprintln(o.Out, "==> group: no prerequisites")
		} else {
			fmt.Fprintf(o.Out, "==> group: requires the fix for defect %s\n", needs)
		}
		if err := build(ctx, o, needs, mode); err != nil {
			return res, err
		}
		for _, c := range cases {
			if c.Needs != needs || (o.Only != "" && o.Only != c.ID) {
				continue
			}
			if _, err := os.Stat(filepath.Join(out, c.Target)); err != nil {
				fmt.Fprintf(o.Out, "  %-19s %-22s SKIP  not built\n", c.ID, c.Target)
				res.Skipped++
				continue
			}
			fmt.Fprintf(o.Out, "  %-19s %-22s ", c.ID, c.Target)
			held, detail := check(ctx, o, out, c)
			// In RED mode a holding assertion is a failure of the suite,
			// because the defect it describes is supposed to be present.
			ok := held == o.Green
			if ok {
				verb := "reproduced"
				if o.Green {
					verb = "fixed"
				}
				fmt.Fprintf(o.Out, "OK   defect %s %s\n", c.Defect, verb)
				res.Expected++
			} else {
				fmt.Fprintf(o.Out, "UNEXPECTED  defect %s: assertion %s in %s mode\n",
					c.Defect, yesno(held), mode)
				fmt.Fprintf(o.Out, "      %s\n", c.Note)
				res.Unexpected++
			}
			if detail != "" {
				fmt.Fprintf(o.Out, "      %s\n", detail)
			}
		}
	}
	fmt.Fprintf(o.Out, "\n%s: %d as expected, %d unexpected, %d skipped\n",
		mode, res.Expected, res.Unexpected, res.Skipped)
	return res, nil
}

func yesno(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

var (
	cassertSu    = regexp.MustCompile(`(?m)^CC="" CXX="" CFLAGS="" CXXFLAGS="" su fuzzuser -c \.\./configure$`)
	cassertPlain = regexp.MustCompile(`(?m)^\.\./configure$`)
	rmProtocol   = regexp.MustCompile(`(?m)^rm protocol_fuzzer$`)
)

// build prepares the clone and runs helper.py.
func build(ctx context.Context, o Options, needs, mode string) error {
	// Start from pristine upstream every time, so a previous run's patches can
	// never leak into this one's result -- which would make green mode pass
	// for the wrong reason and is the single easiest way to fool this suite.
	exec.CommandContext(ctx, "git", "-C", o.Clone, "checkout", "--",
		"projects/"+project).Run()

	bs := filepath.Join(o.Clone, "projects", project, "build.sh")
	b, err := os.ReadFile(bs)
	if err != nil {
		return err
	}
	s := string(b)

	// The oracle, in BOTH modes. Assertions are what make four of the six
	// cases observable at all; without them the defective harness corrupts
	// state quietly instead of aborting. Applying it in both modes keeps the
	// fixes as the only difference between red and green.
	fmt.Fprintln(o.Out, "==> applying the assertion oracle (--enable-cassert)")
	s = cassertSu.ReplaceAllString(s,
		`CC="" CXX="" CFLAGS="" CXXFLAGS="" su fuzzuser -c "../configure --enable-cassert"`)
	s = cassertPlain.ReplaceAllString(s, "../configure --enable-cassert")
	if n := strings.Count(s, "--enable-cassert"); n != 2 {
		return fmt.Errorf("expected 2 configure lines patched, got %d -- upstream build.sh has changed shape", n)
	}

	// Second precondition: keep protocol_fuzzer in the output.
	//
	// build.sh deletes it -- `rm protocol_fuzzer` under a commented-out AFL
	// guard -- so the target cannot be tested at all as things stand. Keeping
	// it is not a fix for defects 4, 5, 7 or 11; it is what makes them
	// observable, in the same way assertions are.
	s = rmProtocol.ReplaceAllString(s,
		"# rm protocol_fuzzer  (test precondition: keep the target buildable)")
	if rmProtocol.MatchString(s) {
		return fmt.Errorf("could not disable the protocol_fuzzer removal")
	}
	if err := os.WriteFile(bs, []byte(s), 0o755); err != nil {
		return err
	}

	// Preconditions. Defect 13 aborts every backend harness at startup with
	// assertions on, so defects 1, 2, 3 and 9 are unobservable until it is in:
	// the first red run reported all four "reproduced" when in fact all four
	// died here, before reaching any behaviour they described.
	pre, _ := filepath.Glob(filepath.Join(o.Root, "tests/ossfuzz/preconditions/*.diff"))
	for _, p := range pre {
		fmt.Fprintf(o.Out, "==> precondition: %s\n", filepath.Base(p))
		if err := apply(ctx, o.Clone, p); err != nil {
			return err
		}
	}

	// Fixes. In green mode, all of them. In red mode, only the ones this group
	// of cases DEPENDS on.
	var fixes []string
	if o.Green {
		fixes, _ = filepath.Glob(filepath.Join(o.Root, "tests/ossfuzz/fixes/*.diff"))
	} else if needs != "" && needs != "-" {
		for _, d := range strings.Split(needs, ",") {
			g, _ := filepath.Glob(filepath.Join(o.Root, "tests/ossfuzz/fixes", d+"-*.diff"))
			fixes = append(fixes, g...)
		}
	}
	for _, p := range fixes {
		fmt.Fprintf(o.Out, "==> fix: %s\n", filepath.Base(p))
		if err := apply(ctx, o.Clone, p); err != nil {
			return err
		}
	}

	fmt.Fprintf(o.Out, "==> building %s from %s (%s)\n", project, o.Clone, mode)
	log, err := os.Create(filepath.Join(o.Clone, "build-"+mode+".log"))
	if err != nil {
		return err
	}
	defer log.Close()
	cmd := exec.CommandContext(ctx, "python3", "infra/helper.py", "build_fuzzers",
		"--sanitizer", "address", "--engine", "libfuzzer", project)
	cmd.Dir = o.Clone
	cmd.Stdout, cmd.Stderr = log, log
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("build failed -- see %s: %w", log.Name(), err)
	}
	built, _ := filepath.Glob(filepath.Join(o.Clone, "build/out", project, "*_fuzzer"))
	fmt.Fprintf(o.Out, "==> built %d target(s)\n", len(built))
	if len(built) == 0 {
		return fmt.Errorf("no targets in build/out/%s", project)
	}
	return nil
}

func apply(ctx context.Context, clone, patch string) error {
	c := exec.CommandContext(ctx, "git", "-C", clone, "apply", patch)
	if out, err := c.CombinedOutput(); err != nil {
		return fmt.Errorf("could not apply %s: %w\n%s", filepath.Base(patch), err, out)
	}
	return nil
}

var (
	trapRe   = regexp.MustCompile(`TRAP: failed Assert\("[^"]*"\)[^,]*`)
	unitsRe  = regexp.MustCompile(`number_of_executed_units: (\d+)`)
	doneRe   = regexp.MustCompile(`Done (\d+) runs`)
	uncovRe  = regexp.MustCompile(`(?m)^.*UNCOVERED_FUNC.*$`)
	coveredF = `(^|[^A-Z])COVERED_FUNC.*\b%s\b`
)

// check returns whether the assertion HOLDS -- the behaviour a fixed harness
// has -- plus a line of evidence for the report.
func check(ctx context.Context, o Options, out string, c Case) (held bool, detail string) {
	args := []string{"run", "--rm", "--privileged", "--shm-size=2g",
		"-e", "FUZZING_ENGINE=libfuzzer", "-e", "SANITIZER=address",
		"-e", "RUN_FUZZER_MODE=interactive", "-e", "HELPER=True"}
	if c.Input != "-" {
		args = append(args, "-v",
			filepath.Join(o.Root, "tests/ossfuzz/inputs", c.Input)+":/testcase:ro")
	}
	// -w and --entrypoint instead of a shell: the container runs the target
	// directly, so nothing here depends on what shell the image happens to
	// ship or on how an argument would have been quoted into one.
	args = append(args, "-v", out+":/out", "-w", "/out",
		"--entrypoint", "/out/"+c.Target, o.Docker)
	if c.Input != "-" {
		args = append(args, "/testcase")
	}
	// Coverage expectations need libFuzzer to list what it reached. Only asked
	// for when a case wants it, because it makes the output far larger.
	if strings.HasPrefix(c.Expect, "covers:") || strings.HasPrefix(c.Expect, "nocover:") {
		args = append(args, "-print_coverage=1")
	}
	// -runs and a short timeout: a case must not be able to hang the suite,
	// and the point is behaviour on one input rather than a fuzzing campaign.
	if c.Input == "-" {
		args = append(args, "-runs=200", "-max_total_time=30")
	}
	// Artifacts go to the container's own /tmp, not into the build. The suite
	// judges by what the target prints, so it never wants them -- and written
	// to /out they would be root-owned files in a directory the host owns.
	args = append(args, "-artifact_prefix=/tmp/")

	cctx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	start := time.Now()
	b, _ := exec.CommandContext(cctx, "docker", args...).CombinedOutput()
	wall := time.Since(start)
	rc := 0
	if cctx.Err() != nil {
		rc = 124
	}
	log := string(b)

	switch {
	case c.Expect == "exit0":
		held = rc == 0

	case strings.HasPrefix(c.Expect, "noassert:"):
		// The discriminating form. A case must name the assertion it expects
		// to stop firing: matching on exit status alone counted two unrelated
		// aborts as six defect reproductions, because an abort is an abort.
		pat := strings.TrimPrefix(c.Expect, "noassert:")
		if t := trapRe.FindString(log); t != "" {
			detail = t
		}
		re, err := regexp.Compile(`TRAP: failed Assert.*(` + pat + `)|(` + pat + `).*failed Assert`)
		held = err == nil && !re.MatchString(log)

	case strings.HasPrefix(c.Expect, "execs>"):
		want, _ := strconv.Atoi(strings.TrimPrefix(c.Expect, "execs>"))
		got := lastInt(unitsRe, log)
		if got == 0 {
			got = lastInt(doneRe, log)
		}
		held = got > want
		detail = fmt.Sprintf("execs=%d (want >%d)", got, want)

	case strings.HasPrefix(c.Expect, "stderr:"):
		held = strings.Contains(log, strings.TrimPrefix(c.Expect, "stderr:"))

	case strings.HasPrefix(c.Expect, "wall<"):
		// The only form that can express "nothing stops this". A timeout that
		// never fires leaves no assertion and no message behind -- the process
		// simply keeps going -- so the clock is the instrument.
		limit, _ := strconv.Atoi(strings.TrimPrefix(c.Expect, "wall<"))
		held = int(wall.Seconds()) < limit
		detail = fmt.Sprintf("wall %ds (limit %ds)", int(wall.Seconds()), limit)

	case strings.HasPrefix(c.Expect, "covers:"):
		// The honest form for a defect whose symptom is "this code is never
		// reached" rather than a crash. Defect 1 does not abort -- it makes
		// the parse of a real statement fail, so the analyser and planner
		// below it are simply never entered. No assertion can express that; a
		// coverage assertion can.
		want := strings.TrimPrefix(c.Expect, "covers:")
		held = covered(log, want)
		if held {
			detail = "reached " + want
		} else {
			detail = "never reached " + want
		}

	case strings.HasPrefix(c.Expect, "nocover:"):
		// The inverse: code that must NOT run. Defect 2 runs its error
		// recovery after a SUCCESSFUL parse, so seeing recovery functions
		// covered on an input that parses cleanly is the defect itself.
		unwant := strings.TrimPrefix(c.Expect, "nocover:")
		if covered(log, unwant) {
			detail = "reached " + unwant + " on a successful input"
		} else {
			held = true
		}
	}

	if !held && detail == "" {
		detail = tailOf(uncovRe.ReplaceAllString(log, ""), 3)
	}
	return held, detail
}

func covered(log, sym string) bool {
	re, err := regexp.Compile(fmt.Sprintf(coveredF, regexp.QuoteMeta(sym)))
	return err == nil && re.MatchString(log)
}

func lastInt(re *regexp.Regexp, s string) int {
	m := re.FindAllStringSubmatch(s, -1)
	if len(m) == 0 {
		return 0
	}
	n, _ := strconv.Atoi(m[len(m)-1][1])
	return n
}

func tailOf(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	out := strings.Join(lines, " ")
	if len(out) > 150 {
		out = out[:150]
	}
	return out
}

package build

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func gitRepo(t *testing.T, subjects ...string) string {
	t.Helper()
	dir := t.TempDir()
	run := func(args ...string) {
		c := exec.Command("git", args...)
		c.Dir = dir
		c.Env = append(c.Environ(),
			"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t",
			"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("init", "-q", "-b", "main")
	for i, subj := range subjects {
		f := filepath.Join(dir, "f")
		if err := writeFile(f, subj+"\n"); err != nil {
			t.Fatal(err)
		}
		run("add", "f")
		run("commit", "-q", "-m", subj, "--allow-empty")
		_ = i
	}
	return dir
}

func writeFile(p, s string) error {
	return os.WriteFile(p, []byte(s), 0o644)
}

// Only AddressSanitizer relocates stack variables, so this refuses an ASan
// build of a tree without the fix -- and refuses rather than warns, because
// such a build reports healthy execution counts and accumulates coverage while
// every utility statement dies at check_stack_depth. A control that cannot run
// the test is worse than no control: it produces numbers.
func TestStackFixRefusesAnASanBuildWithoutIt(t *testing.T) {
	repo := gitRepo(t, "some unrelated commit")
	err := CheckStackFix(repo, "HEAD", "address", "")
	if err == nil {
		t.Fatal("an ASan build without the stack-depth fix was allowed")
	}
	if !strings.Contains(err.Error(), "check_stack_depth") {
		t.Errorf("the refusal does not explain the symptom: %v", err)
	}
}

func TestStackFixAcceptsATreeThatCarriesIt(t *testing.T) {
	repo := gitRepo(t, "Make stack depth check work with asan's use-after-return")
	if err := CheckStackFix(repo, "HEAD", "address", ""); err != nil {
		t.Errorf("a tree containing the fix was refused: %v", err)
	}
}

// A tree pinned to an older minor may carry the fix as a patch= entry.
func TestStackFixAcceptsThePatchSeriesInstead(t *testing.T) {
	repo := gitRepo(t, "some unrelated commit")
	patches := "/src/0003-stack-depth-asan-uar-REL_17_10.patch"
	if err := CheckStackFix(repo, "HEAD", "address", patches); err != nil {
		t.Errorf("a patch supplying the fix was not honoured: %v", err)
	}
}

// ubsan and coverage builds measure stack depth correctly.
func TestStackFixOnlyAppliesToASan(t *testing.T) {
	repo := gitRepo(t, "some unrelated commit")
	for _, san := range []string{"undefined", "coverage"} {
		if err := CheckStackFix(repo, "HEAD", san, ""); err != nil {
			t.Errorf("%s build refused: %v", san, err)
		}
	}
}

package build

import (
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

// StackFixSubject is the upstream commit this check looks for.
//
// "Make stack depth check work with asan's use-after-return", 2026-05-28,
// backpatched through 14 and first released in 16.15 / 17.11 / 18.6.
const StackFixSubject = "Make stack depth check work with asan's use-after-return"

// stackFixPatchHint names a patch that supplies the fix out of tree.
const stackFixPatchHint = "stack-depth-asan-uar"

// CheckStackFix refuses an ASan build of a tree that cannot execute anything.
//
// ONLY AddressSanitizer relocates stack variables, so ubsan and coverage
// builds measure stack depth correctly and are unaffected.
//
// Without the fix, every utility statement dies at check_stack_depth in
// standard_ProcessUtility -- and the build still reports healthy execution
// counts and accumulates coverage, which is why this refuses rather than
// warns. A control that cannot run the test is worse than no control: it
// produces numbers.
//
// A tree pinned to an older minor for other reasons may carry the fix as a
// patch= entry instead, so the patch series is consulted before refusing.
func CheckStackFix(repo, sha, sanitizer, patches string) error {
	if sanitizer != "address" {
		return nil
	}
	if strings.Contains(patches, stackFixPatchHint) {
		return nil
	}
	out, err := exec.Command("git", "-C", repo, "log", "--format=%h",
		"--grep", StackFixSubject, sha).Output()
	if err != nil {
		// An unreadable history is not evidence the fix is absent, and
		// refusing on it would block every build the moment git hiccups.
		return nil
	}
	if strings.TrimSpace(string(out)) != "" {
		return nil
	}
	// A SHALLOW CLONE IS READABLE AND EMPTY, which is not the same as a tree
	// without the fix -- and `git log` on one exits 0, so the guard above for
	// an UNREADABLE history does not catch it.
	//
	// This cost four red CI runs. The fix landed 2026-05-28 and was released
	// in 16.15, 17.11 and 18.6, so the tree can be asked its own version
	// instead of asking history, which works at any depth.
	if isShallow(repo) {
		if v, err := versionOf(repo, sha); err == nil {
			if hasStackFix(v) {
				return nil
			}
		} else {
			// Cannot read the version of a shallow tree either: that is a
			// genuinely unreadable answer, and refusing on it would block a
			// build for a question nobody could answer.
			return nil
		}
	}
	return fmt.Errorf(
		"stack-depth check FAILED: %s predates upstream's %q\n"+
			"  (2026-05-28, backpatched through 14; first released in 16.15 / 17.11 / 18.6),\n"+
			"  and no patch= entry supplies it. Under AddressSanitizer this build cannot\n"+
			"  execute a single utility statement -- every one dies at check_stack_depth in\n"+
			"  standard_ProcessUtility -- while still reporting healthy execution counts and\n"+
			"  accumulating coverage. Refusing to build a control that cannot run the test.\n"+
			"  Move the workspace to a newer minor, or add the cherry-pick to patch=.",
		sha, StackFixSubject)
}

// isShallow reports whether a clone has had its history truncated.
func isShallow(repo string) bool {
	out, err := exec.Command("git", "-C", repo,
		"rev-parse", "--is-shallow-repository").Output()
	return err == nil && strings.TrimSpace(string(out)) == "true"
}

// versionOf reads a tree's own PostgreSQL version from configure.ac.
//
// The tree knows what it is at any clone depth; history does not.
func versionOf(repo, sha string) (string, error) {
	out, err := exec.Command("git", "-C", repo, "show", sha+":configure.ac").Output()
	if err != nil {
		return "", err
	}
	m := reACInit.FindSubmatch(out)
	if m == nil {
		return "", fmt.Errorf("no AC_INIT version in configure.ac at %s", sha)
	}
	return string(m[1]), nil
}

var reACInit = regexp.MustCompile(`AC_INIT\(\[PostgreSQL\], \[([^\]]+)\]`)

// hasStackFix reports whether a PostgreSQL version carries the ASan
// stack-depth fix.
//
// Backpatched through 14 on 2026-05-28 and first released in 16.15, 17.11 and
// 18.6. A development version -- "19devel" -- is newer than any release of its
// major and therefore has it.
func hasStackFix(version string) bool {
	firstWith := map[int]int{16: 15, 17: 11, 18: 6}
	parts := strings.SplitN(version, ".", 2)
	major, err := strconv.Atoi(strings.TrimSuffix(parts[0], "devel"))
	if err != nil {
		return false
	}
	if strings.HasSuffix(parts[0], "devel") {
		return true
	}
	need, known := firstWith[major]
	if !known {
		// Majors after the ones listed shipped with it; earlier ones need a
		// patch= entry, which the caller has already checked for.
		return major > 18
	}
	if len(parts) < 2 {
		return false
	}
	minor, err := strconv.Atoi(strings.SplitN(parts[1], "devel", 2)[0])
	if err != nil {
		// "17devel" style: a development branch of that major, past release.
		return strings.Contains(version, "devel")
	}
	return minor >= need
}

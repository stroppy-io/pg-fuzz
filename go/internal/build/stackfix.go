package build

import (
	"fmt"
	"os/exec"
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

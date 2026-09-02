package incontainer

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

// Repro is the in-container half of a reproduction.
//
// It exists for one reason. OSS-Fuzz's run_fuzzer unconditionally does
//
//	mkdir $OUT/${FUZZER}_${ENGINE}_${SANITIZER}_out
//
// With the build bind-mounted read-write, that mkdir lands IN THE BUILD, owned
// by root, and the host user cannot clear it. 586 of them accumulated across
// the workspaces before anyone looked.
//
// Mounting the build read-only is not the fix: the mkdir then fails and takes
// the whole reproduction with it -- exit 1, no verdict, which reads as "did not
// reproduce" to anything not checking. That was measured, not assumed.
//
// So: the same overlay the fuzzing path uses. The build stays untouched
// underneath, the mkdir lands in a per-run upper layer, and this process
// removes that layer on the way out -- as root, from inside the container,
// which is the only place the permissions are right to do it.
//
// Usage: _repro <reproduce args...>
func Repro(argv []string) int {
	if err := MountOverlay("/out-lower", "/run-ovl/upper", "/run-ovl/work", "/out"); err != nil {
		fmt.Fprintf(os.Stderr, "_repro: %v\n", err)
		return 2
	}
	defer func() {
		// Unmount first: the upper layer is in use until it is not. Step off
		// the mount before doing it -- base-runner's WORKDIR is /out, so this
		// process's own cwd holds it busy otherwise, which is what the first
		// version of this got wrong.
		os.Chdir("/")
		if err := syscall.Unmount("/out", 0); err != nil {
			// MNT_DETACH still lets the removal below proceed.
			if err2 := syscall.Unmount("/out", syscall.MNT_DETACH); err2 != nil {
				fmt.Fprintf(os.Stderr, "_repro: unmount: %v\n", err)
				return
			}
		}
		os.RemoveAll("/run-ovl/upper")
		os.RemoveAll("/run-ovl/work")
	}()

	cmd := exec.Command("reproduce", argv...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	err := cmd.Run()
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode()
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "_repro: %v\n", err)
		return 2
	}
	return 0
}

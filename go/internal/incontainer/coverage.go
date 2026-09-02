package incontainer

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// firstLines keeps an error message short enough to read.
func firstLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, " | ")
}

// CovUnion merges per-target profiles and exports one summary.
//
// Usage: _covunion <object>
//
// The object list is the whole point and the reason this cannot just be
// llvm-cov with a wildcard: coverage_helper builds its list by walking
// DT_NEEDED, and PostgreSQL loads every extension with dlopen -- so no plugin
// is ever linked, none appears, and a report that looks complete covers only
// core. Each .so under tmp_install is added explicitly.
func CovUnion(argv []string) int {
	if len(argv) < 1 {
		fmt.Fprintln(os.Stderr, "_covunion: <object>")
		return 2
	}
	// Everything llvm-cov writes lands in /stage, which is a bind mount from
	// the host and would otherwise stay root-owned.
	defer handBack("/stage")

	obj := "/out/" + argv[0]

	profiles, err := filepath.Glob("/stage/*.profdata")
	if err != nil || len(profiles) == 0 {
		fmt.Fprintln(os.Stderr, "_covunion: no profiles under /stage")
		return 2
	}
	args := append([]string{"merge", "-sparse"}, profiles...)
	args = append(args, "-o", "/stage/union.profdata")
	if out, err := Run("llvm-profdata", args...); err != nil {
		fmt.Fprintf(os.Stderr, "_covunion: llvm-profdata: %v\n%s\n", err, out)
		return 1
	}

	objs := []string{"-object=" + obj}
	// STDOUT only. coverage_helper writes warnings to stderr, and combining
	// the streams puts words like "warning:" into the object list, which
	// llvm-cov then rejects with an error naming none of them.
	if out, err := exec.Command("coverage_helper", "shared_libs",
		"-build-dir=/out", "-object="+obj).Output(); err == nil {
		for _, f := range strings.Fields(string(out)) {
			if strings.HasPrefix(f, "-object=") {
				objs = append(objs, f)
			}
		}
	}
	sos, _ := filepath.Glob(filepath.Join(PGLib("/out"), "*.so"))
	for _, so := range sos {
		objs = append(objs, "-object="+so)
	}

	export := func(extra []string, out string) error {
		a := append([]string{"export"}, extra...)
		a = append(a, "-instr-profile=/stage/union.profdata")
		a = append(a, objs...)
		a = append(a, "-path-equivalence=/,/out")
		c := exec.Command("llvm-cov", a...)
		var errb strings.Builder
		c.Stderr = &errb
		res, err := c.Output()
		if err != nil {
			// The message, not just the status: "exit status 1" sends
			// somebody to read a container's stderr they cannot see.
			return fmt.Errorf("llvm-cov: %w: %s", err, firstLines(errb.String(), 3))
		}
		return os.WriteFile(out, res, 0o644)
	}
	if err := export([]string{"-summary-only"}, "/stage/union-summary.json"); err != nil {
		fmt.Fprintf(os.Stderr, "_covunion: %v\n", err)
		return 1
	}
	fmt.Printf("merged %d profiles over %d objects\n", len(profiles), len(objs))
	return 0
}

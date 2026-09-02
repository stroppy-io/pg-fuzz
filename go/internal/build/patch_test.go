package build

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A workspace patch series must actually reach the tree, and a series that does
// not fit must FAIL rather than leave a half-patched tree that compiles fine
// and fuzzes something nobody intended.
func TestApplyPatches(t *testing.T) {
	write := func(p, s string) {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("applies and records", func(t *testing.T) {
		root := t.TempDir()
		src := filepath.Join(root, "src")
		write(filepath.Join(src, "src/backend/utils/adt/demo.c"),
			"int demo(void) { return 1; }\n")
		good := filepath.Join(root, "good.patch")
		write(good, `--- a/src/backend/utils/adt/demo.c
+++ b/src/backend/utils/adt/demo.c
@@ -1 +1,2 @@
+/* patched by the workspace series */
 int demo(void) { return 1; }
`)
		applied, err := ApplyPatches(src, []string{good}, nil)
		if err != nil {
			t.Fatalf("ApplyPatches: %v", err)
		}
		if len(applied) != 1 || applied[0] != "good.patch" {
			t.Errorf("applied = %v, want [good.patch]", applied)
		}
		b, err := os.ReadFile(filepath.Join(src, "src/backend/utils/adt/demo.c"))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(b), "patched by the workspace series") {
			t.Errorf("the patch did not reach the tree:\n%s", b)
		}
	})

	t.Run("a series that does not fit is an error", func(t *testing.T) {
		root := t.TempDir()
		src := filepath.Join(root, "src")
		write(filepath.Join(src, "src/backend/utils/adt/demo.c"),
			"int demo(void) { return 1; }\n")
		bad := filepath.Join(root, "bad.patch")
		// A hunk past the end of the file. Note what it takes to get here:
		// -F3 is deliberately permissive, so a hunk whose CONTEXT is wrong
		// still applies "with fuzz" -- that is the point, since a patch
		// written against one minor release has to sit on another. What
		// cannot be fuzzed away is a hunk with nowhere to land, and that is
		// what leaves the .rej this gate exists to catch.
		write(bad, `--- a/src/backend/utils/adt/demo.c
+++ b/src/backend/utils/adt/demo.c
@@ -900,4 +900,5 @@
 alpha();
 beta();
+gamma();
 delta();
`)
		_, err := ApplyPatches(src, []string{bad}, nil)
		if err == nil {
			t.Fatal("a rejected hunk must fail the build, not be reported as success")
		}
		if !strings.Contains(err.Error(), "unapplied") {
			t.Errorf("err = %v, want it to say what went wrong", err)
		}
	})

	t.Run("a missing patch is named", func(t *testing.T) {
		root := t.TempDir()
		_, err := ApplyPatches(root, []string{filepath.Join(root, "nope.patch")}, nil)
		if err == nil || !strings.Contains(err.Error(), "nope.patch") {
			t.Errorf("err = %v, want it to name the missing file", err)
		}
	})
}

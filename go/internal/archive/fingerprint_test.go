package archive

import (
	"os"
	"path/filepath"
	"testing"
)

// The fingerprint's VALUE is not the thing to pin -- it changes whenever the
// tree does. What must not drift is which inputs go in, and in what order.
//
// Cross-checked once against the shell implementation this replaced: on the
// live tree, both produced b352aab4 for pg17-ext-all-add and -und. That
// check cannot live in a test (it needs docker and the built binaries), so
// these pin the parts that can be checked hermetically.
func fixture(t *testing.T) FingerprintInputs {
	t.Helper()
	repo, oss, ws := t.TempDir(), t.TempDir(), t.TempDir()
	must := func(p, s string) {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	must(filepath.Join(repo, "project/fuzzer/a.c"), "int a;\n")
	must(filepath.Join(repo, "project/fuzzer/b.h"), "int b;\n")
	must(filepath.Join(oss, "build/out/pgfuzz-w1/BUILD-INFO.json"),
		`{"pg_ref_sha":"abc","plugins":{"z":"1","a":"2"}}`)
	must(filepath.Join(ws, "w1/workspace.conf"),
		"ref=REL_17_10\npatch=/p/one.patch\nplugins=a b\nsanitizer=address\n")
	return FingerprintInputs{Repo: repo, OSSFuzz: oss, WSRoot: ws,
		Workspaces: []string{"w1"}, BaseImage: "img@sha256:deadbeef"}
}

func TestFingerprintIsStableForOneTree(t *testing.T) {
	in := fixture(t)
	a, err := Fingerprint(in)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := Fingerprint(in)
	if a != b || len(a) != 8 {
		t.Errorf("want a stable 8-character hash, got %q then %q", a, b)
	}
}

// Every input that DEFINES the experiment must move the hash. A field that
// silently does not is a field two different runs can differ in while claiming
// to be the same.
func TestEachDefiningInputMovesTheFingerprint(t *testing.T) {
	base := fixture(t)
	want, _ := Fingerprint(base)

	for _, tc := range []struct {
		name string
		mut  func(in *FingerprintInputs)
	}{
		{"base image", func(in *FingerprintInputs) { in.BaseImage = "img@sha256:0000" }},
		{"harness source", func(in *FingerprintInputs) {
			os.WriteFile(filepath.Join(in.Repo, "project/fuzzer/a.c"), []byte("int a2;\n"), 0o644)
		}},
		{"pg sha and plugin pins", func(in *FingerprintInputs) {
			os.WriteFile(filepath.Join(in.OSSFuzz, "build/out/pgfuzz-w1/BUILD-INFO.json"),
				[]byte(`{"pg_ref_sha":"xyz","plugins":{"z":"1","a":"2"}}`), 0o644)
		}},
		{"the patch a workspace applies", func(in *FingerprintInputs) {
			os.WriteFile(filepath.Join(in.WSRoot, "w1/workspace.conf"),
				[]byte("ref=REL_17_10\npatch=/p/other.patch\nplugins=a b\n"), 0o644)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := fixture(t)
			// Rebuild the same tree, then mutate one input.
			got0, _ := Fingerprint(in)
			if got0 != want {
				t.Fatalf("the fixture is not reproducible: %q vs %q", got0, want)
			}
			tc.mut(&in)
			if got, _ := Fingerprint(in); got == want {
				t.Errorf("changing the %s left the fingerprint at %s", tc.name, want)
			}
		})
	}
}

// The sanitizer line and the ref are NOT folded in directly: they reach the
// hash through BUILD-INFO's pg_ref_sha. Renaming a comment in workspace.conf
// must not look like the experiment moved.
func TestUnrelatedConfigDoesNotMoveTheFingerprint(t *testing.T) {
	in := fixture(t)
	want, _ := Fingerprint(in)
	os.WriteFile(filepath.Join(in.WSRoot, "w1/workspace.conf"),
		[]byte("# a new comment\nref=REL_17_10\npatch=/p/one.patch\nplugins=a b\nsanitizer=address\n"), 0o644)
	if got, _ := Fingerprint(in); got != want {
		t.Errorf("a comment changed the fingerprint: %s -> %s", want, got)
	}
}

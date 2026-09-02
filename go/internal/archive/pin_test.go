package archive

import (
	"os"
	"path/filepath"
	"testing"
)

func withPin(t *testing.T, body string) string {
	t.Helper()
	repo := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repo, "project"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, PinFile), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return repo
}

func TestReadPin(t *testing.T) {
	repo := withPin(t, `# a comment
commit=0f4d4d3004beb4946db46905163b1638777395a9
base_image=gcr.io/x/y@sha256:abc

`)
	p, err := ReadPin(repo)
	if err != nil {
		t.Fatal(err)
	}
	if p.Commit != "0f4d4d3004beb4946db46905163b1638777395a9" {
		t.Errorf("commit: %q", p.Commit)
	}
	if p.BaseImage != "gcr.io/x/y@sha256:abc" {
		t.Errorf("base image: %q", p.BaseImage)
	}
}

// A pin naming no commit is not a pin. Accepting it would leave the build gate
// comparing HEAD against "" and passing everything -- the silent-success shape
// this file exists to close.
func TestAPinWithNoCommitIsAnError(t *testing.T) {
	repo := withPin(t, "base_image=gcr.io/x/y@sha256:abc\n")
	if _, err := ReadPin(repo); err == nil {
		t.Error("want an error for a pin with no commit")
	}
}

// A missing pin is distinguishable from an unreadable one, because build
// tolerates the first (a tree that has not pinned yet) and must refuse the
// second.
func TestAMissingPinIsNotFound(t *testing.T) {
	_, err := ReadPin(t.TempDir())
	if !os.IsNotExist(err) {
		t.Errorf("want a not-exist error, got %v", err)
	}
}

// Every mismatch is reported, not just the first: being told the commit is
// wrong, fixing it, and only then being told the image is wrong as well is two
// round trips for one answer.
func TestCheckReportsEveryMismatchAtOnce(t *testing.T) {
	p := Pin{
		Commit:    "0000000000000000000000000000000000000000",
		BaseImage: "gcr.io/nonesuch/nothing@sha256:0000",
	}
	// A directory that is not a git repo: Commit() returns "unknown".
	bad := p.Check(t.TempDir())
	if len(bad) < 2 {
		t.Fatalf("want the commit and the image both reported, got %d: %+v", len(bad), bad)
	}
	for _, m := range bad {
		if m.Fix == "" {
			t.Errorf("%s reported without a fix", m.What)
		}
	}
}

func TestPinRoundTrips(t *testing.T) {
	repo := t.TempDir()
	os.MkdirAll(filepath.Join(repo, "project"), 0o755)
	want := Pin{Commit: "abc123", BaseImage: "gcr.io/x/y@sha256:def"}
	if err := want.Write(repo); err != nil {
		t.Fatal(err)
	}
	got, err := ReadPin(repo)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Errorf("want %+v, got %+v", want, got)
	}
}

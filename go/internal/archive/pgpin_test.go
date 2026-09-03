package archive

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A workspace naming ref=origin/REL_17_STABLE builds whatever that branch is
// TODAY. Correct for a HEAD run and wrong for a comparison: two campaigns a
// week apart are not comparable, and a finding recorded against a branch NAME
// cannot be reproduced later because the name no longer means that commit.
func TestPGPinCatchesARefThatMoved(t *testing.T) {
	repo := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repo, "project"), 0o755); err != nil {
		t.Fatal(err)
	}
	pins := PGPin{"origin/REL_17_STABLE": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	if err := pins.Write(repo); err != nil {
		t.Fatal(err)
	}
	back, err := ReadPGPin(repo)
	if err != nil {
		t.Fatal(err)
	}

	// Unchanged: no complaint.
	if msg := back.Check(repo, "origin/REL_17_STABLE",
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"); msg != "" {
		t.Errorf("a matching pin complained: %s", msg)
	}
	// Moved: named, with both shas.
	msg := back.Check(repo, "origin/REL_17_STABLE",
		"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	if msg == "" {
		t.Fatal("a moved ref was accepted")
	}
	for _, want := range []string{"aaaaaaaaaaaa", "bbbbbbbbbbbb", "not the experiment"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message does not contain %q: %s", want, msg)
		}
	}
}

// PINNING IS PER REF. An unpinned ref still tracks its branch, so a HEAD run
// stays possible -- and stays honest about being one.
func TestUnpinnedRefsAreNotChecked(t *testing.T) {
	p := PGPin{"origin/REL_17_STABLE": "aaaa"}
	if msg := p.Check("", "origin/master", "whatever"); msg != "" {
		t.Errorf("an unpinned ref was checked: %s", msg)
	}
}

// A missing file means nothing is pinned, which is a valid state.
func TestMissingPinFileIsNotAnError(t *testing.T) {
	p, err := ReadPGPin(t.TempDir())
	if err != nil {
		t.Fatalf("a tree with no pins errored: %v", err)
	}
	if len(p) != 0 {
		t.Errorf("invented pins: %v", p)
	}
}

// Sorted, so a diff shows what moved rather than how the map iterated.
func TestPinsAreWrittenSorted(t *testing.T) {
	repo := t.TempDir()
	os.MkdirAll(filepath.Join(repo, "project"), 0o755)
	p := PGPin{"origin/z": "1", "origin/a": "2", "origin/m": "3"}
	if err := p.Write(repo); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(repo, PGPinFile))
	ia := strings.Index(string(b), "origin/a")
	im := strings.Index(string(b), "origin/m")
	iz := strings.Index(string(b), "origin/z")
	if !(ia < im && im < iz) {
		t.Errorf("pins are not sorted:\n%s", b)
	}
}

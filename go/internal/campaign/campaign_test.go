package campaign

import (
	"path/filepath"
	"testing"
)

func TestSeriesSurvivesACorruptTail(t *testing.T) {
	// A campaign killed mid-write leaves a half row. One bad line must not
	// make the history unreadable -- that is the practical argument for JSONL
	// over a single document.
	p := filepath.Join(t.TempDir(), "series.jsonl")
	s := Series{Path: p}
	for i := 1; i <= 3; i++ {
		if err := s.Append(Slice{Round: i, Target: "t", Execs: i * 100}); err != nil {
			t.Fatal(err)
		}
	}
	appendRaw(t, p, `{"round":4,"target":"t","exe`)
	got, err := s.Read()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("read %d rows, want the 3 complete ones", len(got))
	}
}

// Attribution used to be a SECOND implementation of the sweep's rotation,
// mapping a result index back to a target -- and any disagreement between the
// two filed every row under the wrong name while looking entirely plausible.
// The sweep now hands the target to the recorder, so there is nothing to
// disagree with; what is left to check is that the rotation itself is sane.
func TestRotationIsAPermutation(t *testing.T) {
	in := []Entry{{Name: "a"}, {Name: "b"}, {Name: "c"}}
	for by := 0; by < 7; by++ {
		got := rotate(in, by)
		if len(got) != len(in) {
			t.Fatalf("by=%d: %d entries, want %d", by, len(got), len(in))
		}
		seen := map[string]bool{}
		for _, e := range got {
			if seen[e.Name] {
				t.Fatalf("by=%d: %s appears twice", by, e.Name)
			}
			seen[e.Name] = true
		}
	}
	// A prime stride, so neighbours do not share a fate for long: the first
	// workspace of round 1 must not be the first workspace of round 0.
	if rotate(in, 0)[0].Name == rotate(in, 7)[0].Name {
		t.Error("consecutive rounds start on the same workspace")
	}
}

func appendRaw(t *testing.T, path, s string) {
	t.Helper()
	f, err := openAppend(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(s); err != nil {
		t.Fatal(err)
	}
}

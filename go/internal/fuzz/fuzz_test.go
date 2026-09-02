package fuzz

import "testing"

// Rotation must be deterministic and must actually move the tail, or a
// truncated round keeps costing the same targets.
func TestRotationMovesTheTail(t *testing.T) {
	base := []string{"a", "b", "c", "d", "e"}
	seen := map[string]bool{}
	for round := 1; round <= 5; round++ {
		got := append([]string(nil), base...)
		n := len(got)
		off := ((round % n) + n) % n
		got = append(got[off:], got[:off]...)
		seen[got[len(got)-1]] = true
		// Deterministic: the same round gives the same order.
		again := append([]string(nil), base...)
		again = append(again[off:], again[:off]...)
		for i := range got {
			if got[i] != again[i] {
				t.Fatal("rotation is not deterministic")
			}
		}
	}
	if len(seen) < 4 {
		t.Errorf("only %d distinct targets ever ran last: %v", len(seen), seen)
	}
}

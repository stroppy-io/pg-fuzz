package fuzz

import "testing"

// TWO TIERS, DELIBERATELY DIFFERENT.
//
// The shell driver refused to START below one threshold and killed a RUNNING
// slice below a lower one, because refusing costs nothing -- reclaim and retry
// -- while killing a slice costs its round. The port carried the preflight
// into builds and the floor into coverage, and left the fuzz path with
// neither: a campaign grows corpora for hours and is precisely the thing that
// fills a disk, and ENOSPC mid-write can truncate a corpus that took days to
// evolve.
func TestTheDiskTiersAreOrdered(t *testing.T) {
	if DefaultPreflightGB <= DefaultStopFreeGB {
		t.Errorf("preflight %v must be above the running floor %v: refusing to "+
			"start is cheap, killing a running slice is not",
			DefaultPreflightGB, DefaultStopFreeGB)
	}
	if DefaultStopFreeGB <= 0 {
		t.Error("the running floor is disarmed")
	}
}

// Zero disarms the guard, so a caller can opt out explicitly rather than by
// passing a number small enough to never fire.
func TestZeroDisarmsTheFloor(t *testing.T) {
	var r Request
	if r.StopFreeGB != 0 {
		t.Error("the zero value arms the guard; it must be opt-in")
	}
}

// freeGB reports something plausible for a path that exists, and errors rather
// than reporting zero for one that does not -- a guard that reads 0 GB free on
// a bad path would stop every slice it watched.
func TestFreeGBFailsRatherThanReadingZero(t *testing.T) {
	if free, err := freeGB(t.TempDir()); err != nil || free <= 0 {
		t.Errorf("freeGB on a real directory = %v, %v", free, err)
	}
	if _, err := freeGB("/nonexistent-path-for-this-test"); err == nil {
		t.Error("freeGB on a missing path returned no error; a guard would read it as 0 GB free")
	}
}

package build

import "testing"

// A SHALLOW CLONE IS READABLE AND EMPTY, which is not the same as a tree
// without the fix.
//
// CheckStackFix asks `git log --grep` for the upstream commit. On a --depth 1
// clone that exits 0 with no output, so the guard for an UNREADABLE history
// never fires and the build is refused for a question history could not
// answer. Four red CI runs came from this.
//
// The tree knows its own version at any depth: the fix landed 2026-05-28 and
// was released in 16.15, 17.11 and 18.6.
func TestHasStackFixByVersion(t *testing.T) {
	for _, c := range []struct {
		version string
		want    bool
	}{
		{"16.14", false}, {"16.15", true}, {"16.20", true},
		{"17.10", false}, {"17.11", true}, {"17.12", true},
		{"18.5", false}, {"18.6", true},
		{"19devel", true}, // a development branch is past every release
		{"19.0", true},    // majors after 18 shipped with it
		{"15.13", false},  // backpatched through 14 but not released here
	} {
		if got := hasStackFix(c.version); got != c.want {
			t.Errorf("hasStackFix(%q) = %v, want %v", c.version, got, c.want)
		}
	}
}

// Garbage is not a version, and must not read as "has the fix" -- that would
// turn an unparseable tree into a silently ASan-broken build.
func TestHasStackFixRefusesGarbage(t *testing.T) {
	for _, v := range []string{"", "not-a-version", "x.y"} {
		if hasStackFix(v) {
			t.Errorf("hasStackFix(%q) said yes", v)
		}
	}
}

// PRE-RELEASE VERSION STRINGS. PostgreSQL writes 18.6, but also 19beta3,
// 19rc1 and 20devel. The old parse fed all of "19beta3" to Atoi, which fails,
// so it answered "no fix" for a tree that has it -- and REL_19_STABLE's
// address builds were refused on a check that was right about the requirement
// and wrong about the version.
func TestHasStackFixVersionStrings(t *testing.T) {
	for _, c := range []struct {
		version string
		want    bool
		why     string
	}{
		{"19beta3", true, "19 branched after the fix landed in master"},
		{"19rc1", true, "same branch, later pre-release"},
		{"19.0", true, "and its release"},
		{"20devel", true, "master is newer still"},
		{"18.6", true, "the first 18 to carry it"},
		{"18.5", false, "one minor before"},
		{"18beta1", false, "a pre-release of 18 predates 18.6"},
		{"17.11", true, "the first 17 to carry it"},
		{"17.10", false, "one minor before"},
		{"16.15", true, "the first 16 to carry it"},
		{"16.14", false, "one minor before"},
		{"15.20", false, "15 never got it; needs a patch= entry"},
		{"", false, "no version is not a version with the fix"},
		{"garbage", false, "nor is nonsense"},
	} {
		if got := hasStackFix(c.version); got != c.want {
			t.Errorf("hasStackFix(%q) = %v, want %v -- %s", c.version, got, c.want, c.why)
		}
	}
}

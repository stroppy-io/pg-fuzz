package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"pgfuzz/internal/campaign"
)

// A BUILD FROM AN EARLIER RUN IS NOT THIS RUN'S BUILD.
//
// HasBuild is a glob with no timestamp test, so re-running a slug counted last
// week's binaries as this run's and the header's built count was wrong in the
// direction that looks healthy. The Python drew `~` for it and excluded it
// from the count.
func TestFreshnessSeparatesAnEarlierBuild(t *testing.T) {
	slug := t.TempDir()
	bd := campaign.BuildDir(slug, "w")
	if err := os.MkdirAll(bd, 0o755); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(bd, "jsonb_fuzzer")
	if err := os.WriteFile(bin, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}

	old := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(bin, old, old); err != nil {
		t.Fatal(err)
	}
	if got := campaign.Freshness(slug, "w", time.Now().Add(-time.Hour)); got != campaign.StaleBuild {
		t.Errorf("a two-day-old build against an hour-old campaign = %v, want stale", got)
	}
	// Rebuilt now: fresh.
	now := time.Now()
	if err := os.Chtimes(bin, now, now); err != nil {
		t.Fatal(err)
	}
	if got := campaign.Freshness(slug, "w", time.Now().Add(-time.Hour)); got != campaign.FreshBuild {
		t.Errorf("a build made during the campaign = %v, want fresh", got)
	}
	// No build at all stays its own state.
	if got := campaign.Freshness(slug, "nope", time.Now()); got != campaign.NoBuild {
		t.Errorf("no build = %v, want NoBuild", got)
	}
	// NO START TIME MEANS CANNOT TELL, which must read as built rather than
	// as a staleness claim there is no evidence for.
	if got := campaign.Freshness(slug, "w", time.Time{}); got != campaign.FreshBuild {
		t.Errorf("with no start time = %v, want fresh", got)
	}
}

// THE HEADER SAYS WHAT ELAPSED IS MEASURED AGAINST.
//
// Model.Hours was declared and never assigned -- the reader-without-writer
// shape this package's own doc describes -- while campaign.State.Hours sat in
// campaign.json unread. Elapsed alone cannot tell 2h into 24 from 2h into 2.
func TestHeaderShowsTheDeadline(t *testing.T) {
	m := Model{
		Slug: "s", Hours: 24,
		Started:   time.Now().Add(-2 * time.Hour),
		LastSlice: time.Now(),
		Rows:      []Row{{Name: "w"}},
	}
	got := headerClock(m)
	if !strings.Contains(got, "of 24h") {
		t.Errorf("the clock does not say what elapsed is measured against: %q", got)
	}
	if !strings.Contains(got, "left") {
		t.Errorf("the clock does not say how long is left: %q", got)
	}

	// PAST THE DEADLINE IS ITS OWN STATE: in-flight slices finish, no new one
	// starts, and "elapsed 25h of 24h" with nothing else said reads as broken.
	m.Started = time.Now().Add(-25 * time.Hour)
	if got := headerClock(m); !strings.Contains(got, "draining") {
		t.Errorf("past the deadline is not marked: %q", got)
	}

	// No recorded length: elapsed alone, with nothing invented.
	m.Hours = 0
	if got := headerClock(m); strings.Contains(got, " of ") {
		t.Errorf("a campaign with no recorded length claimed one: %q", got)
	}
}

package campaign

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func markerFor(t *testing.T, slugDir string, pid int) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(slugDir, "live"), 0o755); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(State{Slug: filepath.Base(slugDir), PID: pid})
	if err := os.WriteFile(filepath.Join(slugDir, "live", "campaign.json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
}

// Alive means the PID is alive, not that the marker exists. A marker outlives
// kill -9, so trusting the file reports a dead campaign as running forever --
// which would make every later bundle refuse.
func TestLiveDriverTrustsThePidNotTheMarker(t *testing.T) {
	dir := t.TempDir()

	markerFor(t, dir, os.Getpid())
	if LiveDriver(dir) != os.Getpid() {
		t.Error("a running campaign was not detected")
	}

	// A pid that cannot exist: the marker survives, the campaign does not.
	markerFor(t, dir, 0x7ffffffe)
	if got := LiveDriver(dir); got != 0 {
		t.Errorf("a stale marker was read as a live campaign (pid %d)", got)
	}
}

func TestAnyLiveCampaignFindsItAcrossSlugs(t *testing.T) {
	root := t.TempDir()
	markerFor(t, filepath.Join(root, "dead-one"), 0x7ffffffe)
	markerFor(t, filepath.Join(root, "live-one"), os.Getpid())

	slug, pid := AnyLiveCampaign(root)
	if slug != "live-one" || pid != os.Getpid() {
		t.Errorf("AnyLiveCampaign = %q/%d, want live-one/%d", slug, pid, os.Getpid())
	}
}

func TestNoCampaignAtAllIsNotLive(t *testing.T) {
	if slug, pid := AnyLiveCampaign(t.TempDir()); slug != "" || pid != 0 {
		t.Errorf("an empty root reported %q/%d", slug, pid)
	}
}

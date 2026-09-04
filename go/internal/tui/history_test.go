package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"pgfuzz/internal/term"
)

func mkCampaign(t *testing.T, root, slug, started string, sealed bool, entries int) {
	t.Helper()
	d := filepath.Join(root, slug)
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	e := ""
	for i := 0; i < entries; i++ {
		if i > 0 {
			e += ","
		}
		e += `{"workspace":"w"}`
	}
	body := `{"slug":"` + slug + `","started":"` + started +
		`","sealed":` + map[bool]string{true: "true", false: "false"}[sealed] +
		`,"entries":[` + e + `]}`
	if err := os.WriteFile(filepath.Join(d, "MANIFEST.json"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// NEWEST FIRST, BY THE RECORDED START -- not by mtime, because a directory
// touched by a later read is not a later run.
func TestHistoryOrdersByRecordedStart(t *testing.T) {
	root := t.TempDir()
	mkCampaign(t, root, "old", "2026-08-01T00:00:00Z", true, 2)
	mkCampaign(t, root, "new", "2026-09-01T00:00:00Z", false, 5)
	// Touch the old one so mtime disagrees with the record.
	touched := filepath.Join(root, "old", "MANIFEST.json")
	future := time.Now().Add(time.Hour)
	if err := os.Chtimes(touched, future, future); err != nil {
		t.Fatal(err)
	}

	got := History(root, 0)
	if len(got) != 2 {
		t.Fatalf("got %d campaigns, want 2", len(got))
	}
	if got[0].Slug != "new" {
		t.Errorf("first is %q, want the one that started later", got[0].Slug)
	}
	if got[0].Workspaces != 5 || got[1].Workspaces != 2 {
		t.Errorf("workspace counts wrong: %+v", got)
	}
}

// A RUN MISSING FROM A HISTORY READS AS A RUN THAT NEVER HAPPENED, so a
// directory whose manifest cannot be read is listed and marked.
func TestHistoryListsWhatItCannotRead(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "no-manifest"), 0o755); err != nil {
		t.Fatal(err)
	}
	got := History(root, 0)
	if len(got) != 1 || !got[0].Broken {
		t.Fatalf("got %+v, want one row marked broken", got)
	}

	var scr term.Screen
	scr.Reset(20, 100)
	scr.Plain = true
	drawHistory(&scr, Model{History: got})
	if !strings.Contains(scr.Text(), "manifest not read") {
		t.Errorf("the unreadable run is not marked:\n%s", scr.Text())
	}
}

// The limit keeps the newest, not an arbitrary slice.
func TestHistoryLimitKeepsTheNewest(t *testing.T) {
	root := t.TempDir()
	mkCampaign(t, root, "a", "2026-01-01T00:00:00Z", true, 1)
	mkCampaign(t, root, "b", "2026-06-01T00:00:00Z", true, 1)
	mkCampaign(t, root, "c", "2026-09-01T00:00:00Z", true, 1)

	got := History(root, 2)
	if len(got) != 2 || got[0].Slug != "c" || got[1].Slug != "b" {
		t.Errorf("got %v, want the two newest", got)
	}
}

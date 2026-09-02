package main

import (
	"os"
	"path/filepath"
	"testing"

	"pgfuzz/internal/paths"
)

func roots(t *testing.T) paths.Roots {
	t.Helper()
	ws := t.TempDir()
	for _, d := range []string{
		"campaigns/pg17-ext-all/live",
		"campaigns/pg17-ext-all/pg17-ext-all-20260828-7ef7a089/logs",
		"pg17-ext-all-und/corpus",
		"not-a-workspace/corpus",
	} {
		if err := os.MkdirAll(filepath.Join(ws, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// A workspace is identified by its conf, not its name.
	if err := os.WriteFile(filepath.Join(ws, "pg17-ext-all-und", "workspace.conf"),
		[]byte("ref=REL_17_10\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return paths.Roots{WS: ws}
}

func TestResolveCampaignAcceptsWhatIsNaturalToType(t *testing.T) {
	r := roots(t)
	const want = "pg17-ext-all"
	for _, tc := range []struct{ name, arg string }{
		{"the slug itself", want},
		{"its directory", filepath.Join(r.Campaigns(), want)},
		{"something inside it", filepath.Join(r.Campaigns(), want, "live")},
		{"a sealed archive", filepath.Join(r.Campaigns(), want, want+"-20260828-7ef7a089")},
		{"deep inside an archive", filepath.Join(r.Campaigns(), want, want+"-20260828-7ef7a089", "logs")},
		{"a workspace of it", filepath.Join(r.WS, want+"-und")},
		{"a workspace subdirectory", filepath.Join(r.WS, want+"-und", "corpus")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveCampaign(tc.arg, r)
			if err != nil {
				t.Fatalf("%s: %v", tc.arg, err)
			}
			if got != want {
				t.Errorf("%s resolved to %q, want %q", tc.arg, got, want)
			}
		})
	}
}

// A typo must be an error. Resolving it to whatever ran most recently is how
// the dashboard opened on a campaign that had ended in August while another
// was fuzzing.
func TestResolveCampaignRefusesRatherThanGuessing(t *testing.T) {
	r := roots(t)
	for _, arg := range []string{
		"pg17-ext-al",                          // a typo
		"pg99-nonesuch",                        // never existed
		r.Campaigns(),                          // the campaigns root itself names no campaign
		filepath.Join(r.WS, "not-a-workspace"), // a directory with no workspace.conf
	} {
		if got, err := resolveCampaign(arg, r); err == nil {
			t.Errorf("%q resolved to %q; want an error", arg, got)
		}
	}
}

// Standing somewhere unrelated is an error that says what to do, not a silent
// fallback to some other campaign.
func TestResolveCampaignFromAnUnrelatedDirectory(t *testing.T) {
	r := roots(t)
	wd, _ := os.Getwd()
	defer os.Chdir(wd)
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Skip("cannot change directory")
	}
	_, err := resolveCampaign("", r)
	if err == nil {
		t.Fatal("want an error when standing outside any campaign")
	}
	if !contains(err.Error(), "-slug") {
		t.Errorf("the error should say how to name one: %v", err)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

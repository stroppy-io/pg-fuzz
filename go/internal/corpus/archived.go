package corpus

import (
	"os"
	"path/filepath"
	"strings"
)

// ARCHIVED INPUTS ARE STILL COVERAGE.
//
// minimize renames rather than deletes: `<target>.premin.<stamp>` is the
// corpus before a merge, `<target>.capped.<stamp>` is what an autocap dropped.
// Both live under `<ws>/corpus-backups/`, and both are real inputs that once
// reached real code.
//
// Seed walked only `<ws>/corpus/<target>`, so a coverage workspace seeded from
// a fuzzing one measured the LIVE corpus and never the archived reach -- the
// old driver put the gap at roughly 641,000 inputs across two workspaces.
//
// The distinction the shell drew explicitly: replay cost bounds FUZZING, so a
// capped corpus is the right thing to fuzz. An input that reached new code
// once still counts for COVERAGE, so it is the wrong thing to leave out of a
// measurement.

// BackupDirs lists a workspace's archived corpora for one target, newest last.
func BackupDirs(wsDir, target string) []string {
	root := filepath.Join(wsDir, "corpus-backups")
	ents, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		n := e.Name()
		// Both conventions, and only for THIS target: a prefix match alone
		// would pull jsonb_fuzzer's archives into jsonpath_fuzzer's.
		if strings.HasPrefix(n, target+".premin.") ||
			strings.HasPrefix(n, target+".capped.") {
			out = append(out, filepath.Join(root, n))
		}
	}
	// ReadDir is sorted by name and the stamps sort chronologically, so this
	// is newest last without a second stat.
	return out
}

// SeedArchived copies a workspace's archived inputs into a destination corpus.
//
// FOR COVERAGE, NOT FOR FUZZING. A caller seeding a workspace it intends to
// fuzz should not use this: the inputs were archived precisely because
// replaying them costs more than they return. A coverage workspace wants them
// all.
func SeedArchived(srcWS, dstRoot string, targets []string) (SeedResult, error) {
	var total SeedResult
	for _, t := range targets {
		for _, bak := range BackupDirs(srcWS, t) {
			dst := filepath.Join(dstRoot, t)
			if err := os.MkdirAll(dst, 0o755); err != nil {
				return total, err
			}
			ents, err := os.ReadDir(bak)
			if err != nil {
				continue
			}
			for _, e := range ents {
				if e.IsDir() {
					continue
				}
				out := filepath.Join(dst, e.Name())
				if _, err := os.Stat(out); err == nil {
					total.Present++
					continue
				}
				if err := copyFile(filepath.Join(bak, e.Name()), out); err != nil {
					total.Failed++
					if total.FirstErr == nil {
						total.FirstErr = err
					}
					continue
				}
				total.Copied++
			}
		}
	}
	return total, nil
}

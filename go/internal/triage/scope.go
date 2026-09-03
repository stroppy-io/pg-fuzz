package triage

import (
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// reWorkspaceTok matches a workspace name as written in a write-up.
//
// Workspace names are lowercase, hyphenated, and end in a sanitizer suffix or
// are bare families like pg17-10-ext or oriolebare17. Matching loosely and
// filtering by the caller's pattern is safer than trying to enumerate them.
var reWorkspaceTok = regexp.MustCompile(`\b(?:pg|oriole|oriolebare|gt|vfy)[a-z0-9]*(?:-[a-z0-9]+)*\b`)

// WorkspacesNamed lists the workspace names a write-up mentions.
//
// BY MENTION, WHICH IS NOT A RECORD. No field in a write-up says which
// campaign produced it: **Build:** exists in six of twenty-eight and only for
// OrioleDB, and **Found:** carries a date and a target, not a workspace. So
// the only available attribution is the names the author happened to type in
// the prose, and a report built on it has to say so rather than present it as
// provenance.
func WorkspacesNamed(text string) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range reWorkspaceTok.FindAllString(text, -1) {
		// A bare family word is not a workspace: "pg17" alone names a
		// version, and counting it would sweep in every write-up that
		// mentions the major.
		if !strings.Contains(m, "-") {
			continue
		}
		if !seen[m] {
			seen[m] = true
			out = append(out, m)
		}
	}
	sort.Strings(out)
	return out
}

// InScope reports whether a write-up names a workspace matching any pattern,
// and which ones it named.
//
// Patterns are shell globs over the workspace name -- "pg17-10-ext-*" -- so a
// caller can ask for one campaign, one family, or one sanitizer.
func InScope(text string, patterns []string) ([]string, bool) {
	if len(patterns) == 0 {
		return nil, true
	}
	var hit []string
	for _, ws := range WorkspacesNamed(text) {
		for _, p := range patterns {
			if ok, _ := filepath.Match(p, ws); ok {
				hit = append(hit, ws)
				break
			}
		}
	}
	return hit, len(hit) > 0
}

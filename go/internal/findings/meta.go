package findings

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// MissingMeta lists finding directories with no **Found by:** line.
//
// WHY A GATE AND NOT A BACKFILL. The backfill has run: every finding on disk
// carries the field. Attribution used to be recoverable only by reading prose
// and guessing -- two of twenty-four write-ups stated it outright and the rest
// had to be inferred from whichever fuzzer the text happened to name -- and
// the field is what ended that. Nothing stops the next write-up being added
// without one, at which point the reports quietly go back to inferring.
//
// WHAT THIS FIELD DOES NOT DO, because it is easy to assume otherwise: it
// names the TARGET, not the campaign. A report still cannot say which run
// produced a finding, which is a separate gap needing a separate field.
func MissingMeta(root string) []string {
	ents, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range ents {
		if !e.IsDir() || !isFindingDir(e.Name()) {
			continue
		}
		b, err := os.ReadFile(filepath.Join(root, e.Name(), "README.md"))
		if err != nil {
			// No write-up at all is a worse version of the same problem.
			out = append(out, e.Name())
			continue
		}
		if Field(string(b), "Found by") == "" {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out
}

// isFindingDir excludes what is not a finding: dotfiles (FINDINGS is its own
// git repo, and .git counted as a PostgreSQL-core finding once), the reports
// directory, and the dated campaign records.
func isFindingDir(name string) bool {
	switch {
	case strings.HasPrefix(name, "."):
		return false
	case name == "reports":
		return false
	case len(name) >= 5 && name[:2] == "20" && name[4] == '-':
		return false
	}
	return true
}

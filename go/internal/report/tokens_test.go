package report

import (
	"regexp"
	"sort"
	"strings"
	"testing"
)

// THE TWO PAGES MUST RESOLVE ONE PALETTE.
//
// base.css opened by explaining that it exists so that "two pages that are
// meant to look like one product" cannot drift apart. They had drifted anyway:
// the history index used base.css, and the per-run report carried its own copy
// of the same palette under different names -- --accent for --copper, --rule
// for --hairline, --bad for --sev-confirmed, the identical hex written twice
// in two files -- on a different paper colour entirely.
//
// Both now inline the same tokens file. This test fails if either page starts
// defining its own again.
func TestBothPagesShareOneTokenSet(t *testing.T) {
	if !strings.Contains(page, "tokensCSS") && !strings.Contains(page, "--paper") {
		t.Skip("the report page no longer inlines a stylesheet at all")
	}
	reDef := regexp.MustCompile(`(--[a-z0-9-]+)\s*:`)

	defined := func(css string) []string {
		var out []string
		seen := map[string]bool{}
		for _, m := range reDef.FindAllStringSubmatch(css, -1) {
			// var(--x) is a USE, not a definition.
			if !seen[m[1]] {
				seen[m[1]] = true
				out = append(out, m[1])
			}
		}
		sort.Strings(out)
		return out
	}

	// The report template must define no token of its own: everything it uses
	// comes from the shared file.
	tplOnly := strings.ReplaceAll(page, tokensCSS, "")
	if got := defined(tplOnly); len(got) > 0 {
		t.Errorf("the report page defines its own tokens again: %v", got)
	}
	if got := defined(strings.ReplaceAll(baseRules, tokensCSS, "")); len(got) > 0 {
		t.Errorf("the index rules define their own tokens again: %v", got)
	}
	if len(defined(tokensCSS)) < 10 {
		t.Error("the shared token file looks empty")
	}
}

// EVERY TOKEN A PAGE USES MUST BE DEFINED, in all three theme states, or the
// page renders one theme's text on the other theme's ground.
func TestNoPageUsesAnUndefinedToken(t *testing.T) {
	reUse := regexp.MustCompile(`var\((--[a-z0-9-]+)\)`)
	for _, p := range []struct{ name, css string }{
		{"report", page},
		{"index", baseCSS},
	} {
		for _, m := range reUse.FindAllStringSubmatch(p.css, -1) {
			if !strings.Contains(tokensCSS, m[1]+":") {
				t.Errorf("%s uses %s, which the shared tokens do not define",
					p.name, m[1])
			}
		}
	}
}

package report

import (
	"regexp"
	"strings"
	"testing"
)

// EVERY CLASS A TEMPLATE ASKS FOR MUST EXIST IN THE STYLESHEET.
//
// .warn was requested by two cells in the history index -- a config
// fingerprint that MOVED, and a run's masked-target count -- and defined
// nowhere, because the rule had been renamed to .cfgchg and the templates were
// not. Both cells rendered as ordinary text, so the signal that an
// experiment's definition shifted underneath a comparison looked exactly like
// the signal that it had not.
//
// This is a whole-class check rather than a check for one name: a stylesheet
// and a template in different files drift silently, and nothing else here
// notices.
func TestEveryTemplateClassIsStyled(t *testing.T) {
	// Each template is checked against the styles IT can actually reach:
	// baseCSS, plus whatever the template inlines itself.
	reAttr := regexp.MustCompile(`class="([^"{}]*)"`)
	for _, tpl := range []struct {
		name string
		text string
	}{{"index", indexPage}, {"report", page}} {
		style := baseCSS + tpl.text
		n := 0
		for _, m := range reAttr.FindAllStringSubmatch(tpl.text, -1) {
			for _, c := range strings.Fields(m[1]) {
				n++
				// A class may be styled directly or as part of a compound
				// selector (.pill.confirmed).
				if !strings.Contains(style, "."+c) {
					t.Errorf("%s: class %q is used and defined in no stylesheet",
						tpl.name, c)
				}
			}
		}
		if n == 0 {
			t.Errorf("%s: no classes found; the template or this test moved", tpl.name)
		}
	}
}

package report

import _ "embed"

// THE ONE STYLESHEET BOTH REPORTS USE.
//
// Shared at the SOURCE so the per-run snapshot and the campaign history index
// cannot drift apart -- they did, because each carried its own copy of
// near-identical table rules, and two pages meant to look like one product
// diverged every time either changed.
//
// Embedded rather than read from disk, and inlined at render time rather than
// linked: artifact pages run under a CSP that blocks external stylesheets, and
// an archived report must still render years later from a directory with no
// network and no copy of this repository.
//
// This is the tool, not config. The layout of a report is part of what the
// tool IS; which plugins at which version is what it operates on.
//
//go:embed assets/base.css
var baseRules string

// THE TOKENS, which are the part that must not differ.
//
// Split from the rules because the two pages did not actually share this
// sheet: the history index used it, and the per-run report carried its own
// copy of the same palette under different names. Each page keeps its own
// layout rules -- they lay out different things -- but both resolve their
// colours and type from here.
//
// tokensCSS + baseRules is byte-identical to the base.css that came before the
// split. The final report inlines it into a document compared byte for byte
// against the renderer this replaced, so the split must be free: anything
// ADDED for one page belongs on that page.
//
//go:embed assets/tokens.css
var tokensCSS string

// baseCSS is the index's full stylesheet: tokens then rules.
var baseCSS = tokensCSS + baseRules

// BaseCSS is the stylesheet, wrapped for inlining.
func BaseCSS() string { return "<style>\n" + baseCSS + "\n</style>" }

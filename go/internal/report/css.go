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
var baseCSS string

// BaseCSS is the stylesheet, wrapped for inlining.
func BaseCSS() string { return "<style>\n" + baseCSS + "\n</style>" }

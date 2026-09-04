package tui

import "strings"

// ROW FILTERING, which the Python had and the port dropped.
//
// The old dashboard took --only GLOB and cycled --filter all|active|live with
// `f`, and printed an "N/M rows" note so a short grid never looked like the
// filter had been ignored. On a 24-row matrix with two live workspaces there
// was no way to narrow.

// Filter is which rows the grid shows.
type Filter int

const (
	// FilterAll shows every declared workspace, including ones that have not
	// produced a slice: a workspace missing from the grid reads as a
	// workspace that does not exist.
	FilterAll Filter = iota
	// FilterActive shows workspaces with a build, i.e. ones this campaign can
	// actually fuzz.
	FilterActive
	// FilterLive shows only what is fuzzing or building right now.
	FilterLive
)

func (f Filter) String() string {
	switch f {
	case FilterActive:
		return "active"
	case FilterLive:
		return "live"
	}
	return "all"
}

// Next cycles the filter, as `f` did.
func (f Filter) Next() Filter {
	if f == FilterLive {
		return FilterAll
	}
	return f + 1
}

// Apply returns the rows to draw and how many there were in total.
//
// BOTH NUMBERS, because a filtered grid that does not say it is filtered is
// indistinguishable from a campaign that lost workspaces.
func Apply(rows []Row, f Filter, only string) (shown []Row, total int) {
	total = len(rows)
	for _, r := range rows {
		if only != "" && !matchGlob(only, r.Name) {
			continue
		}
		switch f {
		case FilterActive:
			if !r.Built && !r.Building {
				continue
			}
		case FilterLive:
			if r.Running == "" && !r.Building && r.Covering == "" {
				continue
			}
		}
		shown = append(shown, r)
	}
	return shown, total
}

// matchGlob is a `*` glob over a workspace name.
//
// Written out rather than filepath.Match because a workspace name is not a
// path: filepath.Match refuses to let `*` cross a separator, and these names
// are full of hyphens that people expect a glob to span.
func matchGlob(pat, s string) bool {
	parts := strings.Split(pat, "*")
	if len(parts) == 1 {
		return pat == s
	}
	if !strings.HasPrefix(s, parts[0]) {
		return false
	}
	s = s[len(parts[0]):]
	for i := 1; i < len(parts)-1; i++ {
		j := strings.Index(s, parts[i])
		if j < 0 {
			return false
		}
		s = s[j+len(parts[i]):]
	}
	return strings.HasSuffix(s, parts[len(parts)-1])
}

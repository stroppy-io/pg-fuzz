package tui

import (
	"fmt"
	"time"

	"pgfuzz/internal/campaign"
	"pgfuzz/internal/term"
)

// WHAT THE SLICES DID, which soak-status showed and the dashboard does not.
//
// The shell's status printed slices written this run split finished from
// in-flight, and of the finished how many were SILENT -- "the ratchet cannot
// use those" -- plus stale logs from earlier runs it was ignoring, and the
// corpus rate. None of that is on the dashboard: silence is detected only at
// gate time, which is after the round, and a corpus growing at 200/hour looks
// identical to one growing at 20,000.

// Slices is the run's slice accounting.
type Slices struct {
	Finished int
	Silent   int
	InFlight int
	// CorpusNow and CorpusRate are the total across the campaign's workspaces
	// and its growth per hour, measured over the run rather than guessed from
	// the newest slice.
	CorpusNow  int
	CorpusRate float64
}

// SliceStats summarises a campaign's own series.
//
// SILENT IS COUNTED SEPARATELY. A slice that reported no executions is not a
// slice that ran badly -- it is a slice whose numbers cannot be used, and the
// ratchet skips it. Folding the two together makes a round of 23 look complete
// when four of it are unusable.
func SliceStats(rows []campaign.Slice, inFlight int, started, now time.Time) Slices {
	var s Slices
	s.InFlight = inFlight
	byWS := map[string]int{}
	for _, r := range rows {
		s.Finished++
		if r.Execs == 0 && !r.Alive {
			s.Silent++
		}
		// Newest per workspace wins: corpus is a level, not an increment.
		if r.Corpus > 0 {
			byWS[r.Workspace] = r.Corpus
		}
	}
	for _, n := range byWS {
		s.CorpusNow += n
	}
	if h := now.Sub(started).Hours(); h > 0.05 && s.CorpusNow > 0 {
		// Over the run's own clock. A rate from the newest slice alone swings
		// wildly between rounds and says nothing about the campaign.
		grown := 0
		first := map[string]int{}
		for _, r := range rows {
			if _, seen := first[r.Workspace]; !seen && r.CorpusBefore > 0 {
				first[r.Workspace] = r.CorpusBefore
			}
		}
		for ws, now := range byWS {
			grown += now - first[ws]
		}
		if grown > 0 {
			s.CorpusRate = float64(grown) / h
		}
	}
	return s
}

func drawSlices(s *term.Screen, m Model, y int) int {
	if m.SliceStats.Finished == 0 && m.SliceStats.InFlight == 0 {
		return y
	}
	st := m.SliceStats
	line := fmt.Sprintf("slices: %d finished", st.Finished)
	if st.InFlight > 0 {
		line += fmt.Sprintf(", %d in flight", st.InFlight)
	}
	if st.Silent > 0 {
		// SAID IN COLOUR, because it is the number that invalidates the
		// others: the ratchet cannot use a slice that reported nothing.
		line += term.Yellow +
			fmt.Sprintf("   %d SILENT (no executions -- the ratchet cannot use those)", st.Silent) +
			term.Reset
	}
	if st.CorpusNow > 0 {
		line += fmt.Sprintf("   corpus %s", comma(st.CorpusNow))
		if st.CorpusRate > 0 {
			line += fmt.Sprintf(" (~%s/hour)", comma(int(st.CorpusRate)))
		}
	}
	s.Line(y, term.Dim+line+term.Reset)
	return y + 2
}

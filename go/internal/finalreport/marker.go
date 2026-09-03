package finalreport

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

// THE MARKER HAD A READER AND NO WRITER.
//
// ReadStoppedAt parses it, MarkerPath says where it lives, and the bundle
// inventory lists it as one of the documents a campaign leaves behind -- and
// nothing in this program ever wrote one. So the final report's "stopped at"
// was empty for every campaign this tool has run, and the inventory named a
// file that could not exist.
//
// It records two things a bundle cannot reconstruct afterwards: WHEN the run
// stopped, and how big each corpus was AT THAT MOMENT. The second is what lets
// somebody check that the corpus shipped in a bundle is the corpus the numbers
// were measured against, rather than one that kept growing after the report
// was written.

// CorpusCount is one target's corpus size at the moment of stop.
type CorpusCount struct {
	Workspace string
	Target    string
	Inputs    int
}

// WriteStopMarker records when a campaign stopped and what its corpora held.
//
// Sorted, because this file is diffed between runs and Go's map iteration
// would otherwise reorder it on every write for no reason.
func WriteStopMarker(path string, stoppedAt time.Time, counts []CorpusCount) error {
	sorted := append([]CorpusCount(nil), counts...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Workspace != sorted[j].Workspace {
			return sorted[i].Workspace < sorted[j].Workspace
		}
		return sorted[i].Target < sorted[j].Target
	})

	var b strings.Builder
	// The format the reader already expects: local time, seconds resolution.
	fmt.Fprintf(&b, "stopped_at=%s\n", stoppedAt.Format("2006-01-02 15:04:05"))
	if len(sorted) > 0 {
		fmt.Fprintf(&b, "workspace=%s\n", sorted[0].Workspace)
	}
	for _, c := range sorted {
		fmt.Fprintf(&b, "corpus\t%s\t%s\t%d\n", c.Workspace, c.Target, c.Inputs)
	}
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

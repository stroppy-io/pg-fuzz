package campaign

import (
	"os"
	"sync"
	"time"
)

// A CACHED SERIES READ, for callers that read it repeatedly.
//
// WHY. The dashboard rebuilds its whole model once a second, and did so by
// reading and unmarshalling the entire series -- twice, once for the rows and
// once to list the workspaces. Measured on a 100,000-slice series that is 225
// ms a frame: a 22% duty cycle, continuous, on the box doing the fuzzing.
//
// Interval's comment already says a faster loop "spends CPU the campaign
// wants and produces an identical frame". That reasoning bounds how OFTEN the
// work happens and says nothing about what it costs, and the cost grows with
// the length of the campaign -- so the longer a run goes, the more of it the
// dashboard takes.
//
// Slices arrive minutes apart. Almost every frame parses a file that has not
// changed.
//
// CORRECT RATHER THAN MERELY FAST. The key is the file's size and modification
// time together, and the series is append-only, so any new slice changes the
// size. A cache that answered from a stale file would be the same class of
// defect as everything else here -- a confident, wrong number -- so it
// revalidates on every call and re-reads the moment either differs.
var seriesCache sync.Map // path -> *seriesEntry

type seriesEntry struct {
	mu    sync.Mutex
	size  int64
	mtime time.Time
	rows  []Slice
}

// ReadCached is Read, without re-parsing a file that has not changed.
//
// The returned slice is SHARED between callers and must not be modified. It is
// handed to readers that aggregate it, which is every caller today.
func (s Series) ReadCached() ([]Slice, error) {
	fi, err := os.Stat(s.Path)
	if err != nil {
		return nil, err
	}
	v, _ := seriesCache.LoadOrStore(s.Path, &seriesEntry{})
	e := v.(*seriesEntry)

	e.mu.Lock()
	defer e.mu.Unlock()
	if e.rows != nil && e.size == fi.Size() && e.mtime.Equal(fi.ModTime()) {
		return e.rows, nil
	}
	rows, err := s.Read()
	if err != nil {
		return nil, err
	}
	e.size, e.mtime, e.rows = fi.Size(), fi.ModTime(), rows
	return rows, nil
}

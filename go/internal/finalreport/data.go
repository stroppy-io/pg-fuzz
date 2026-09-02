package finalreport

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Data is what the gather writes and the renderer reads.
//
// Field names match the JSON the previous implementation wrote, so an archived
// data.json from either tool renders with either renderer. The archives are
// write-once; a schema that only the newest code can read makes them
// unreadable exactly when they matter.
type Data struct {
	Workspaces map[string]WorkspaceData `json:"workspaces"`
	// CARRIED AS RAW JSON, not re-modelled. These rows come from the coverage
	// tooling and carry fields this report does not read -- "regions", for one
	// -- and a struct here would silently drop them on the way through. The
	// data file is shipped in the bundle and re-rendered later; dropping a
	// field nobody reads today is how it stops being there tomorrow.
	Coverage   map[string]json.RawMessage `json:"coverage"`
	Components map[string]json.RawMessage `json:"components"`
	Patches    []Patch                    `json:"patches"`
	Runtime    Runtime                    `json:"runtime"`
	Masked     Masked                     `json:"masked"`
	// "inventory", NOT "components": the coverage breakdown already owns that
	// key. Adding this one under the same name silently overwrote it, and the
	// per-component coverage table vanished from the report -- a section that
	// simply stopped rendering, with nothing failing to say so.
	Inventory json.RawMessage `json:"inventory"`
	Findings  Findings        `json:"findings"`
	Generated string          `json:"generated"`
}

// WorkspaceData is one build's contribution.
type WorkspaceData struct {
	Targets     map[string]TargetRow `json:"targets"`
	CorpusTotal int                  `json:"corpus_total"`
	SeriesRound *int                 `json:"series_round"`
}

// TargetRow is one target within one build.
type TargetRow struct {
	Corpus         int            `json:"corpus"`
	CorpusArchived int            `json:"corpus_archived"`
	ExecFloor      *int           `json:"exec_floor"`
	RateFloor      *Rate          `json:"rate_floor"`
	SeriesExecs    *int           `json:"series_execs"`
	SeriesNewUnits *int           `json:"series_new_units"`
	SeriesCorpus   *int           `json:"series_corpus"`
	SeriesRows     int            `json:"series_rows"`
	Log            LogStats       `json:"log"`
	Artifacts      map[string]int `json:"artifacts"`
}

// LogStats is what one target's slice log says it did.
type LogStats struct {
	Inited   *int           `json:"inited"`
	Done     *int           `json:"done"`
	Execs    int            `json:"execs"`
	NewUnits int            `json:"new_units"`
	Runs     int            `json:"runs"`
	Seconds  int            `json:"seconds"`
	Bytes    int64          `json:"bytes"`
	Errors   map[string]int `json:"errors"`
}

// CoverageRow is one target's measured coverage.
type CoverageRow struct {
	Target    string    `json:"target"`
	When      string    `json:"when"`
	PassID    string    `json:"pass_id"`
	Lines     CovCounts `json:"lines"`
	Functions CovCounts `json:"functions"`
	Branches  CovCounts `json:"branches"`
}

// CovCounts is a covered-of-total pair.
type CovCounts struct {
	Count   int `json:"count"`
	Covered int `json:"covered"`
}

// ComponentsRow is one target's coverage split by component.
// Order is carried alongside the map. Components with the same covered count
// are ranked by the order the coverage tool emitted them, and Go's map
// iteration is RANDOMISED -- so without this the component table came out in a
// different order on every render, which is wrong on its own terms: a report
// that shuffles its own rows between runs cannot be diffed.
type ComponentsRow struct {
	Target     string                  `json:"target"`
	When       string                  `json:"when"`
	Components map[string]ComponentCov `json:"components"`
	Order      []string                `json:"-"`
}

// ComponentCov is one component's share.
type ComponentCov struct {
	Lines CovCounts `json:"lines"`
}

// Union is the merged profile across every target.
type Union struct {
	Lines               CovCounts `json:"lines"`
	Functions           CovCounts `json:"functions"`
	Branches            CovCounts `json:"branches"`
	LinesInEnteredFiles CovCounts `json:"lines_in_entered_files"`
	FilesEntered        int       `json:"files_entered"`
	FilesTotal          int       `json:"files_total"`
}

// GatherWorkspaces reads the per-target state of each build.
func GatherWorkspaces(wsRoot string, workspaces []string, baselinePath, seriesPath string) map[string]WorkspaceData {
	var base struct {
		Floors     map[string]map[string]int     `json:"floors"`
		RateFloors map[string]map[string]float64 `json:"rate_floors"`
	}
	if b, err := os.ReadFile(baselinePath); err == nil {
		_ = json.Unmarshal(b, &base)
	}
	series := readFullSeries(seriesPath)

	out := map[string]WorkspaceData{}
	for _, ws := range workspaces {
		wsdir := filepath.Join(wsRoot, ws)
		floors, rfloors := base.Floors[ws], base.RateFloors[ws]

		// EACH TARGET'S OWN LATEST VALUE. Soak writes ONE-TARGET rows, so the
		// last row describes whichever target finished last and reads null for
		// every other one -- the same bug class as "the last four rows" in the
		// productivity ordering.
		var rowsWS []fullSeriesRow
		for _, r := range series {
			if r.WS == ws {
				rowsWS = append(rowsWS, r)
			}
		}
		perT := map[string]map[string]int{}
		rowsSeen := map[string]int{}
		for _, r := range rowsWS {
			for f, m := range map[string]map[string]int{
				"execs": r.Execs, "new_units": r.NewUnits, "corpus": r.Corpus,
			} {
				for t, v := range m {
					if perT[t] == nil {
						perT[t] = map[string]int{}
					}
					perT[t][f] = v
				}
			}
			for t := range r.Execs {
				rowsSeen[t]++
			}
		}
		var latestRound *int
		if len(rowsWS) > 0 {
			latestRound = rowsWS[len(rowsWS)-1].Round
		}

		ents, _ := os.ReadDir(filepath.Join(wsdir, "corpus"))
		var targets []string
		for _, e := range ents {
			if strings.HasSuffix(e.Name(), "_fuzzer") {
				targets = append(targets, e.Name())
			}
		}
		sort.Strings(targets)

		rows := map[string]TargetRow{}
		total := 0
		for _, t := range targets {
			archived := 0
			bak := filepath.Join(wsdir, "corpus-backups")
			if bs, err := os.ReadDir(bak); err == nil {
				for _, d := range bs {
					if strings.HasPrefix(d.Name(), t) || strings.HasPrefix(d.Name(), "."+t) {
						archived += countDir(filepath.Join(bak, d.Name()))
					}
				}
			}
			r := TargetRow{
				Corpus:         countDir(filepath.Join(wsdir, "corpus", t)),
				CorpusArchived: archived,
				SeriesRows:     rowsSeen[t],
				Log:            ReadLogStats(filepath.Join(wsdir, "soak-"+t+".log")),
				Artifacts:      ArtifactCounts(wsdir, t),
			}
			if v, ok := floors[t]; ok {
				r.ExecFloor = &v
			}
			if v, ok := rfloors[t]; ok {
				rv := Rate(v)
				r.RateFloor = &rv
			}
			if v, ok := perT[t]["execs"]; ok {
				r.SeriesExecs = &v
			}
			if v, ok := perT[t]["new_units"]; ok {
				r.SeriesNewUnits = &v
			}
			if v, ok := perT[t]["corpus"]; ok {
				r.SeriesCorpus = &v
			}
			rows[t] = r
			total += r.Corpus
		}
		out[ws] = WorkspaceData{Targets: rows, CorpusTotal: total, SeriesRound: latestRound}
	}
	return out
}

type fullSeriesRow struct {
	WS       string         `json:"ws"`
	Round    *int           `json:"round"`
	Execs    map[string]int `json:"execs"`
	NewUnits map[string]int `json:"new_units"`
	Corpus   map[string]int `json:"corpus"`
}

func readFullSeries(path string) []fullSeriesRow {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []fullSeriesRow
	dec := json.NewDecoder(f)
	for {
		var r fullSeriesRow
		if err := dec.Decode(&r); err != nil {
			break
		}
		out = append(out, r)
	}
	return out
}

func countDir(p string) int {
	ents, err := os.ReadDir(p)
	if err != nil {
		return 0
	}
	return len(ents)
}

// ArtifactCounts are RAW libFuzzer artifacts for one target.
//
// These are NOT distinct defects. libFuzzer writes one file per input that
// triggered something, so a single signature hit repeatedly produces hundreds.
// Reporting these as "findings" would overstate by more than an order of
// magnitude; the triaged, de-duplicated count lives in FINDINGS.
func ArtifactCounts(wsdir, target string) map[string]int {
	out := map[string]int{"crash": 0, "oom": 0, "timeout": 0}
	ents, err := os.ReadDir(filepath.Join(wsdir, "artifacts", target))
	if err != nil {
		return out
	}
	for _, e := range ents {
		for _, k := range []string{"crash", "oom", "timeout"} {
			if strings.HasPrefix(e.Name(), k) {
				out[k]++
				break
			}
		}
	}
	return out
}

// ReadCoverage reads the newest row per target from a coverage series.
//
// Only rows with a line count: a row that measured nothing is not the newest
// measurement of anything, and letting one overwrite a real row turns a
// finished measurement into a blank.
func ReadCoverage(path string) map[string]json.RawMessage {
	return readRawSeries(path, func(raw json.RawMessage) (string, bool) {
		var r CoverageRow
		if json.Unmarshal(raw, &r) != nil || r.Lines.Count == 0 {
			return "", false
		}
		return r.Target, true
	})
}

// ReadComponents reads the newest component breakdown per target.
func ReadComponents(path string) map[string]json.RawMessage {
	return readRawSeries(path, func(raw json.RawMessage) (string, bool) {
		var r ComponentsRow
		if json.Unmarshal(raw, &r) != nil {
			return "", false
		}
		return r.Target, true
	})
}

func readRawSeries(path string, key func(json.RawMessage) (string, bool)) map[string]json.RawMessage {
	out := map[string]json.RawMessage{}
	f, err := os.Open(path)
	if err != nil {
		return out
	}
	defer f.Close()
	dec := json.NewDecoder(f)
	for {
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			break
		}
		if k, ok := key(raw); ok {
			out[k] = raw
		}
	}
	return out
}

// DecodeCoverage parses the rows the renderer needs, leaving the raw form
// untouched for the data file.
func DecodeCoverage(m map[string]json.RawMessage) map[string]CoverageRow {
	out := make(map[string]CoverageRow, len(m))
	for k, raw := range m {
		var r CoverageRow
		if json.Unmarshal(raw, &r) == nil {
			out[k] = r
		}
	}
	return out
}

// DecodeComponents does the same for the component breakdown, recovering the
// key order the JSON was written in.
func DecodeComponents(m map[string]json.RawMessage) map[string]ComponentsRow {
	out := make(map[string]ComponentsRow, len(m))
	for k, raw := range m {
		var r ComponentsRow
		if json.Unmarshal(raw, &r) != nil {
			continue
		}
		r.Order = objectKeyOrder(raw, "components")
		out[k] = r
	}
	return out
}

// objectKeyOrder returns the keys of one nested object in the order they
// appear in the document.
//
// encoding/json gives a map, and a map has no order. The token stream does.
func objectKeyOrder(raw json.RawMessage, field string) []string {
	dec := json.NewDecoder(bytes.NewReader(raw))
	depth := 0
	inField := false
	var out []string
	for {
		t, err := dec.Token()
		if err != nil {
			return out
		}
		switch v := t.(type) {
		case json.Delim:
			switch v {
			case '{', '[':
				depth++
			case '}', ']':
				depth--
				if inField && depth <= 1 {
					return out
				}
			}
		case string:
			if depth == 1 && v == field {
				inField = true
				continue
			}
			if inField && depth == 2 {
				out = append(out, v)
				// Skip this key's value wholesale, so keys nested inside it
				// are not mistaken for siblings.
				var skip json.RawMessage
				if dec.Decode(&skip) != nil {
					return out
				}
			}
		}
	}
}

// ReadUnion returns the LAST union row, which is the newest.
func ReadUnion(path string) *Union {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var last *Union
	dec := json.NewDecoder(f)
	for {
		var u Union
		if err := dec.Decode(&u); err != nil {
			break
		}
		v := u
		last = &v
	}
	return last
}

// Rate is a throughput floor that keeps its decimal point, matching how the
// baseline stores it. Go's default encoding writes an integral float as
// "111527" where the file says "111527.0"; the data file is shipped and
// diffed, so the two must agree.
type Rate float64

func (r Rate) MarshalJSON() ([]byte, error) {
	s := strconv.FormatFloat(float64(r), 'f', -1, 64)
	if !strings.ContainsAny(s, ".eE") {
		s += ".0"
	}
	return []byte(s), nil
}

func (r *Rate) UnmarshalJSON(b []byte) error {
	f, err := strconv.ParseFloat(strings.TrimSpace(string(b)), 64)
	if err != nil {
		return err
	}
	*r = Rate(f)
	return nil
}

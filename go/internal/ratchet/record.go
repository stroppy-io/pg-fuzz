package ratchet

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Recording what happened, so the second layer has something to read.
//
// TWO FILES, AND THEY ANSWER DIFFERENT QUESTIONS.
//
// The HISTORY records only MOVES, which is the wrong data for a detector: a
// target decaying steadily never beats its record, so it writes nothing and
// looks -- in a transition log -- exactly like a target nobody is running.
//
// The SERIES records every round's observation for every target whether or not
// it changed. That is ~733 integers a round, small enough to keep forever, and
// the only thing that makes CUSUM possible at all.
//
// Both are JSONL rather than fields inside the baseline: the baseline is a
// snapshot people read, and burying a growing audit trail inside it would make
// every diff unreadable -- costing exactly the reviewability it exists for.

// SeriesRecord is one line of the series.
type SeriesRecord struct {
	WS         string         `json:"ws"`
	Round      *int           `json:"round"`
	Log        *string        `json:"log"`
	LogMTime   *string        `json:"log_mtime"`
	ToolCommit *string        `json:"tool_commit"`
	Execs      map[string]int `json:"execs"`
	NewUnits   map[string]int `json:"new_units"`
	Corpus     map[string]int `json:"corpus"`
	RunID      *string        `json:"run_id"`
	CPUSecs    *float64       `json:"cpu_secs"`
	Cov        *int           `json:"cov"`
	Ft         *int           `json:"ft"`
	Secs       *int           `json:"secs"`
	Jobs       *int           `json:"jobs"`
}

// HistoryRecord is one line of the history.
type HistoryRecord struct {
	WS         string            `json:"ws"`
	Round      *int              `json:"round"`
	Log        *string           `json:"log"`
	LogMTime   *string           `json:"log_mtime"`
	ToolCommit *string           `json:"tool_commit"`
	Build      map[string]string `json:"build"`
	Changes    []Change          `json:"changes"`
}

// AppendJSONL writes one record, creating the file if needed.
//
// O_APPEND, and one Write of the whole line: concurrent slices append to this
// file at the same time, and a write split into several calls interleaves into
// two half-lines that neither parses nor can be repaired.
func AppendJSONL(path string, v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(append(raw, '\n'))
	return err
}

// CorpusSizes counts inputs per target for one workspace.
//
// Counted here, once per round, and NOT in the dashboard: counting every
// corpus on this machine is 29 million files and 34.6 seconds, which at a
// three-second refresh is impossible, and caching does not save it because the
// directories being fuzzed are exactly the ones that keep changing.
//
// ONLY real target directories. A read of everything counts anything parked
// beside the corpora -- a backup, a scratch dir -- as an extra target and adds
// it to the workspace total, and that total decides whether a corpus has
// stopped growing. A stray directory does not just distort a display number,
// it moves a plateau decision.
func CorpusSizes(wsDir string) map[string]int {
	out := map[string]int{}
	root := filepath.Join(wsDir, "corpus")
	ents, err := os.ReadDir(root)
	if err != nil {
		return out
	}
	for _, e := range ents {
		if !e.IsDir() || !strings.HasSuffix(e.Name(), "_fuzzer") {
			continue
		}
		inner, err := os.ReadDir(filepath.Join(root, e.Name()))
		if err != nil {
			continue
		}
		out[e.Name()] = len(inner)
	}
	return out
}

// CPUSecs reads the processor seconds written beside a slice log while the
// container was alive.
//
// Distinct from secs x jobs, which is what the slice was ALLOWED: the
// postmaster-backed targets spend most of a slice waiting rather than
// computing, so the two differ by more than an order of magnitude and only one
// of them is work done.
func CPUSecs(log string) *float64 {
	if log == "" {
		return nil
	}
	p := log + ".cpu"
	if strings.HasSuffix(log, ".log") {
		p = strings.TrimSuffix(log, ".log") + ".cpu"
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return nil
	}
	v, err := strconv.ParseFloat(strings.TrimSpace(string(b)), 64)
	if err != nil {
		return nil
	}
	return &v
}

// LogMTime is the log's modification time in UTC, or nil when there is no log.
func LogMTime(log string) *string {
	if log == "" {
		return nil
	}
	fi, err := os.Stat(log)
	if err != nil {
		return nil
	}
	// Microseconds and an explicit +00:00 offset, matching every row already
	// in these files. The analyses filter by STRING PREFIX, so a file holding
	// two timestamp formats answers --since differently depending on which
	// tool wrote the row.
	//
	// ROUNDED to the microsecond, not truncated: Go's Format truncates, and a
	// row written here would sort a microsecond before the identical row
	// written by the tool that came before -- which for a prefix filter is a
	// difference that can include or exclude a round.
	s := fi.ModTime().UTC().Round(time.Microsecond).Format("2006-01-02T15:04:05.000000-07:00")
	return &s
}

// ToolCommit identifies the tool that wrote a record.
func ToolCommit(repo string) *string {
	out, err := exec.Command("git", "-C", repo, "rev-parse", "--short", "HEAD").Output()
	if err != nil {
		return nil
	}
	s := strings.TrimSpace(string(out))
	if s == "" {
		return nil
	}
	return &s
}

// BuildProvenance is what the workspace was built from -- ref, sha, sanitizer.
func BuildProvenance(wsDir string) map[string]string {
	info := map[string]string{}
	filepath.WalkDir(filepath.Join(wsDir, "builds"), func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || d.Name() != "BUILD-INFO.json" {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		var j struct {
			PGRefSHA  string `json:"pg_ref_sha"`
			Sanitizer string `json:"sanitizer"`
			BuiltAt   string `json:"built_at"`
		}
		if json.Unmarshal(b, &j) != nil {
			return nil
		}
		info["pg_sha"], info["sanitizer"], info["built_at"] = j.PGRefSHA, j.Sanitizer, j.BuiltAt
		return filepath.SkipAll
	})
	if b, err := os.ReadFile(filepath.Join(wsDir, "workspace.conf")); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(line, "#") || !strings.Contains(line, "=") {
				continue
			}
			k, v, _ := strings.Cut(line, "=")
			if (k == "ref" || k == "sanitizer") && v != "" {
				info[k] = v
			}
		}
	}
	return info
}

// Expired lists acknowledgements that are no longer needed.
//
// The half people forget. A free pass that outlives its cause looks like
// diligence, and is the reason the table this replaced became unreadable.
func Expired(obs []Observation, floors map[string]int, acks map[string]string, tol float64) []string {
	var out []string
	for _, o := range obs {
		if _, ok := acks[o.Target]; !ok {
			continue
		}
		// The absolute minimum keeps a target that is merely above a tiny
		// floor from looking recovered.
		if float64(o.Execs) >= float64(floors[o.Target])*tol && o.Execs >= 10000 {
			out = append(out, o.Target)
		}
	}
	return out
}

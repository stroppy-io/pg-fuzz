// Package ratchet keeps numbers from going backwards without somebody saying so.
//
// A flat floor -- "at least 10,000 executions" -- cannot see a target that
// falls from 264,893 to 20,000. That happened: simple_query_fuzzer dropped to
// 192 executions on 2026-08-17 and every gate passed it, because 192 is a
// number and nobody was comparing it to anything. The ratchet compares each
// target against its own record.
//
// THE TOLERANCE IS A TENTH, AND THAT IS NOT A TYPO
// ===============================================
// A run passes at `observed >= floor * 0.1`. Fuzzing is genuinely noisy --
// corpus growth alone changes replay cost between rounds -- so a tight floor
// would fail honest runs and get switched off, and a gate that is switched off
// catches nothing. A tenth still catches the collapse it exists for.
//
// REGIMES, WHICH ARE THE SUBTLE PART
// ==================================
// A floor earned at four jobs says nothing about a run at one. Comparing them
// fails the honest run and teaches everyone to ignore the gate. So each floor
// records the regime that earned it, and a floor from another regime is
// SKIPPED and said so -- not silently passed, and not failed.
package ratchet

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"syscall"
)

// DefaultTolerance is the fraction of the floor a run must reach.
const DefaultTolerance = 0.1

// Baseline is the record every workspace is judged against.
type Baseline struct {
	Version    int                          `json:"version"`
	Tolerance  float64                      `json:"tolerance"`
	Floors     map[string]map[string]int    `json:"floors"`
	Regimes    map[string]map[string]string `json:"regimes"`
	RateFloors map[string]map[string]Rate   `json:"rate_floors"`
	// Fields this tool does not interpret are carried as raw JSON so a save
	// returns them byte for byte. Modelling them means guessing their shape,
	// and the first guess was wrong -- `notes` is an array, not a map, which
	// made the whole baseline fail to parse. Worse than failing would have
	// been succeeding and dropping somebody's notes on the next write.
	Notes   json.RawMessage `json:"notes,omitempty"`
	Reseeds json.RawMessage `json:"reseeds,omitempty"`
	Archive json.RawMessage `json:"floors_archive,omitempty"`

	// archiveAll is the decoded form, held only while an update is running.
	// The raw field stays authoritative so every other workspace's entries
	// survive a save byte for byte.
	archiveAll map[string]map[string]map[string]int
}

// Load reads a baseline.
func Load(path string) (Baseline, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Baseline{}, err
	}
	var out Baseline
	if err := json.Unmarshal(b, &out); err != nil {
		return Baseline{}, fmt.Errorf("ratchet baseline: %w", err)
	}
	if out.Tolerance == 0 {
		out.Tolerance = DefaultTolerance
	}
	return out, nil
}

// Save writes a baseline back.
//
// Through a temporary and a rename: a campaign updates this between rounds
// while a status command may be reading it, and a half-written baseline reads
// as a workspace with no floors at all -- which passes everything.
func (b Baseline) Save(path string) error {
	raw, err := b.marshalSorted()
	if err != nil {
		return err
	}
	// tmp + rename, and the temp name carries THIS PROCESS's pid.
	//
	// A fixed ".tmp" is a shared name: 32 slices finish concurrently, and two
	// of them writing the same scratch file interleave into one corrupt
	// document that the rename then publishes. The pid makes each write its
	// own file, and the rename makes a reader see either the whole old file or
	// the whole new one -- never a half-written one.
	tmp := fmt.Sprintf("%s.tmp.%d", path, os.Getpid())
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(raw, '\n')); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

// WithLock serialises a read-modify-write of the baseline across concurrent
// slices.
//
// The baseline is read-modify-written by EVERY slice, and there are 32 in
// flight. Two hazards follow from doing that unlocked:
//
//	Lost updates.  A reads, B reads, A writes, B writes -- and A's raised floor
//	is gone. Nothing reports it, because B's write succeeded.
//
//	Truncated reads.  A writer that empties the file before filling it lets a
//	concurrent reader see nothing, and "no floors" read as a pass.
//
// The lock is a separate file, not the baseline itself: locking the file that
// is about to be replaced by rename means the lock and the data part company
// at exactly the moment it matters.
func WithLock(path string, fn func() error) error {
	fd, err := syscall.Open(path+".lock", syscall.O_CREAT|syscall.O_RDWR, 0o644)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	if err := syscall.Flock(fd, syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(fd, syscall.LOCK_UN)
	return fn()
}

// Observation is what one target did in one round.
type Observation struct {
	Target string
	Execs  int
	Rate   float64 // executions per second, when the run length is known
	// NewUnits is recorded beside the execution count, NOT gated on.
	//
	// Executions are a proxy for "is this target working" and a bad one:
	// spi_query_fuzzer reported a few hundred every round for months while
	// adding ZERO new inputs, and xlogreader_fuzzer does fifteen million
	// executions and also adds zero because its corpus is saturated. Neither
	// number alone separates those two.
	NewUnits int
	Regime   string // "jobs=4"
}

// Outcome is how one target was judged.
type Outcome int

const (
	Pass         Outcome = iota
	Regressed            // below the floor, and nobody has acknowledged it
	Acknowledged         // below the floor, and somebody said why
	Incomparable         // the floor was earned under a different regime
	NoFloor              // never measured here before
)

// Judgement is one target's result.
type Judgement struct {
	Target   string
	Outcome  Outcome
	Observed int
	Floor    int
	Regime   string
	Earned   string // the regime the floor was earned under
	Note     string

	// Which floor decided this. A verdict that does not say whether it read
	// executions or a rate cannot be checked against the baseline by hand,
	// and the two differ by four orders of magnitude.
	ByRate    bool
	Rate      float64
	RateFloor float64

	// ExecFloorSkipped says the execution floor was not comparable this round
	// even though the rate floor was. Reported, not fatal.
	ExecFloorSkipped bool
}

// Report is a whole workspace's result.
type Report struct {
	Workspace string
	Seeded    bool // there was no baseline at all
	Judged    []Judgement
}

// Failed reports whether anything regressed unacknowledged.
func (r Report) Failed() bool {
	for _, j := range r.Judged {
		if j.Outcome == Regressed {
			return true
		}
	}
	return false
}

// Check judges one round against the baseline.
//
// An absent baseline is NOT a pass and says so: a floor cannot be regressed
// from before it exists, and reporting that as success is how a workspace with
// no history looks identical to one that is healthy.
func Check(b Baseline, ws string, obs []Observation, acks map[string]string) Report {
	rep := Report{Workspace: ws}
	floors := b.Floors[ws]
	if len(floors) == 0 {
		rep.Seeded = true
		return rep
	}
	regimes := b.Regimes[ws]
	rateFloors := b.RateFloors[ws]
	tol := b.Tol()

	// judge applies the tolerance to whichever pair of numbers the caller
	// decided is comparable, and downgrades a regression the acknowledgement
	// list already explains.
	judge := func(o Observation, acks map[string]string, observed, limit float64,
		execFloor int, byRate bool) Judgement {
		j := Judgement{Target: o.Target, Observed: o.Execs, Floor: execFloor,
			Regime: o.Regime, ByRate: byRate, Rate: o.Rate, RateFloor: limit}
		if !byRate {
			j.RateFloor = 0
		}
		if observed >= limit*tol {
			j.Outcome = Pass
			return j
		}
		// An acknowledged target is capped by a known cause, so its throughput
		// is expected to sit far below what it once managed. Report, do not
		// fail -- the acknowledgement is the decision, made in a commit.
		if why, ok := acks[o.Target]; ok {
			j.Outcome, j.Note = Acknowledged, why
			return j
		}
		j.Outcome = Regressed
		return j
	}

	for _, o := range obs {
		// PREFER THE RATE, AND PREFER IT FIRST.
		//
		// An absolute execution floor cannot be compared across modes: a soak
		// slice is 20x a round's budget, so it executes ~20x as much, and a
		// floor earned in one mode is either trivially cleared or permanently
		// unreachable in the other. Per-worker-second throughput is
		// independent of both budget and job count.
		//
		// That independence is why the rate floor is tested BEFORE the regime
		// check below, not after it. Skipping a target whose EXEC floor is
		// incomparable also threw away a rate floor that was perfectly
		// comparable -- and that let a round pass at 8.5% of a rate floor it
		// had already achieved, on a target this gate exists to catch.
		if rf, ok := rateFloors[o.Target]; ok && o.Rate > 0 {
			j := judge(o, acks, o.Rate, float64(rf), floors[o.Target], true)
			// The exec floor's comparability is still worth REPORTING even
			// when the rate decided the verdict: it says that floor is not
			// protecting anything this round, which is the sort of quiet
			// coverage loss this whole package exists to surface.
			if earned, has := regimes[o.Target]; has || floors[o.Target] > 0 {
				if o.Regime != "" && earned != o.Regime {
					j.ExecFloorSkipped, j.Earned = true, earned
				}
			}
			rep.Judged = append(rep.Judged, j)
			continue
		}

		floor, ok := floors[o.Target]
		if !ok {
			rep.Judged = append(rep.Judged, Judgement{
				Target: o.Target, Outcome: NoFloor, Observed: o.Execs})
			continue
		}
		// A floor earned at four jobs says nothing about a run at one.
		//
		// AND A FLOOR WITH NO RECORDED REGIME IS LEGACY: earned before regimes
		// were tracked, across a mix of job counts and budgets, so it is not
		// known to be comparable to ANYTHING. Treating it as comparable is
		// what produced 7 of 22 targets sitting below a tenth of their floor
		// while fuzzing perfectly well.
		//
		// So legacy floors are skipped too, once. The next update stamps them
		// with the regime that actually produced them and they resume
		// protecting. That follows the precedent already set for rate floors:
		// one pass without regression cover is the honest price of not
		// inventing a baseline.
		if earned := regimes[o.Target]; o.Regime != "" && earned != o.Regime {
			rep.Judged = append(rep.Judged, Judgement{
				Target: o.Target, Outcome: Incomparable, Observed: o.Execs,
				Floor: floor, Regime: o.Regime, Earned: earned})
			continue
		}

		rep.Judged = append(rep.Judged, judge(o, acks, float64(o.Execs), float64(floor), floor, false))
	}
	sort.Slice(rep.Judged, func(i, j int) bool {
		return rep.Judged[i].Target < rep.Judged[j].Target
	})
	return rep
}

// Update raises floors that were beaten.
//
// Only upward, and only for the regime the run was in. Lowering a floor
// because a run was slow is how a ratchet stops being one -- the record is
// what the target HAS done, not what it did last.
func (b *Baseline) Update(ws string, obs []Observation) UpdateResult {
	res := UpdateResult{}
	if b.Floors == nil {
		b.Floors = map[string]map[string]int{}
	}
	if b.Regimes == nil {
		b.Regimes = map[string]map[string]string{}
	}
	if b.RateFloors == nil {
		b.RateFloors = map[string]map[string]Rate{}
	}
	for _, m := range []any{} {
		_ = m
	}
	if b.Floors[ws] == nil {
		b.Floors[ws] = map[string]int{}
	}
	if b.Regimes[ws] == nil {
		b.Regimes[ws] = map[string]string{}
	}
	if b.RateFloors[ws] == nil {
		b.RateFloors[ws] = map[string]Rate{}
	}
	floors, regs, rfloors := b.Floors[ws], b.Regimes[ws], b.RateFloors[ws]
	arch := b.archive(ws)

	// RATE FLOORS MOVE INDEPENDENTLY of exec floors.
	//
	// They are the regime-independent half of the record, so a round that does
	// not beat its execution count can still set a throughput record -- and an
	// earlier version only touched the rate when the exec floor rose, which
	// meant a rate floor could never be established for a target whose exec
	// floor was already high.
	for _, o := range obs {
		if o.Rate <= 0 {
			continue
		}
		switch old, had := rfloors[o.Target]; {
		case !had:
			rfloors[o.Target] = Rate(o.Rate)
			res.RateAdded++
		case Rate(o.Rate) > old:
			rfloors[o.Target] = Rate(o.Rate)
			res.RateRaised++
		}
	}

	// Regime bookkeeping. A floor from another regime is ARCHIVED rather than
	// discarded -- switching back restores it -- and the new regime starts
	// from what this run actually did.
	rkey := ""
	for _, o := range obs {
		if o.Regime != "" {
			rkey = o.Regime
			break
		}
	}
	if rkey != "" {
		for t, v := range floors {
			if prev := regs[t]; prev != "" && prev != rkey {
				if arch[t] == nil {
					arch[t] = map[string]int{}
				}
				arch[t][prev] = v
				res.Switched = append(res.Switched, Switch{t, prev, v})
				delete(floors, t)
				delete(regs, t)
			}
		}
	}
	sort.Slice(res.Switched, func(i, j int) bool { return res.Switched[i].Target < res.Switched[j].Target })

	for _, o := range obs {
		// STAMP THE REGIME on every target seen, not only on the ones that
		// moved. This is what lets a legacy floor -- one with no recorded
		// regime, skipped because it is not known to be comparable to anything
		// -- resume protecting after one round. Without it the skip is
		// permanent and the ratchet quietly stops being one.
		if rkey != "" {
			regs[o.Target] = rkey
		}
		old, had := floors[o.Target]
		// A floor archived under THIS regime before is the record to beat.
		if !had {
			if prev, ok := arch[o.Target][rkey]; ok {
				old, had = prev, true
				floors[o.Target] = prev
			}
		}
		switch {
		case !had:
			floors[o.Target] = o.Execs
			res.Added++
			res.Changes = append(res.Changes, Change{Target: o.Target, Kind: "record", To: o.Execs})
		case o.Execs > old:
			// Only ever upward. A tool that can quietly lower its own bar is
			// not a ratchet; lowering is a hand edit in a reviewable commit.
			floors[o.Target] = o.Execs
			res.Raised++
			from := old
			res.Changes = append(res.Changes, Change{Target: o.Target, Kind: "raise", From: &from, To: o.Execs})
		}
	}
	sort.Slice(res.Changes, func(i, j int) bool { return res.Changes[i].Target < res.Changes[j].Target })
	b.setArchive(ws, arch)
	return res
}

// UpdateResult is what one update did, in enough detail to write the history.
type UpdateResult struct {
	Added, Raised         int
	RateAdded, RateRaised int
	Switched              []Switch
	Changes               []Change
}

// Switch is a floor archived because the regime changed under it.
type Switch struct {
	Target, From string
	Value        int
}

// Change is one state transition, as the history records it.
type Change struct {
	Target string `json:"target"`
	Kind   string `json:"kind"` // record | raise
	From   *int   `json:"from"`
	To     int    `json:"to"`
}

// archive decodes floors_archive, which this type otherwise carries verbatim.
func (b *Baseline) archive(ws string) map[string]map[string]int {
	all := map[string]map[string]map[string]int{}
	if len(b.Archive) > 0 {
		_ = json.Unmarshal(b.Archive, &all)
	}
	if all[ws] == nil {
		all[ws] = map[string]map[string]int{}
	}
	b.archiveAll = all
	return all[ws]
}

func (b *Baseline) setArchive(ws string, a map[string]map[string]int) {
	if b.archiveAll == nil {
		b.archiveAll = map[string]map[string]map[string]int{}
	}
	b.archiveAll[ws] = a
	if raw, err := json.Marshal(b.archiveAll); err == nil {
		b.Archive = raw
	}
}

// Regime is the key that decides whether two floors are comparable.
// Deliberately just the job count.
func Regime(jobs int) string {
	if jobs < 1 {
		jobs = 1
	}
	return fmt.Sprintf("jobs=%d", jobs)
}

// Tol is the tolerance in force, defaulting when the baseline does not say.
//
// A missing tolerance must not read as zero: zero passes everything, which is
// the silent-success direction this package exists to avoid.
func (b Baseline) Tol() float64 {
	if b.Tolerance > 0 {
		return b.Tolerance
	}
	return DefaultTolerance
}

// Rate is a throughput floor that keeps its decimal point.
//
// Go's default float encoding writes an integral value as "63471", where the
// tool that came before wrote "63471.0". Both parse to the same number, but
// the baseline is COMMITTED and read by people: a save that silently rewrites
// hundreds of unrelated values produces a diff in which the one floor that
// actually moved is invisible.
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

// marshalSorted writes the baseline with its TOP-LEVEL KEYS IN SORTED ORDER.
//
// A struct marshals its fields in declaration order, which would reorder the
// whole committed file on the first save by this tool. Nested maps already
// sort, so ordering the top level is all that is needed to make a save that
// changes one floor produce a diff showing one floor.
func (b Baseline) marshalSorted() ([]byte, error) {
	raw, err := json.Marshal(b)
	if err != nil {
		return nil, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var out []byte
	out = append(out, '{', '\n')
	for i, k := range keys {
		var pretty bytes.Buffer
		if err := json.Indent(&pretty, fields[k], "  ", "  "); err != nil {
			return nil, err
		}
		out = append(out, "  "...)
		kb, _ := json.Marshal(k)
		out = append(out, kb...)
		out = append(out, ": "...)
		out = append(out, pretty.Bytes()...)
		if i < len(keys)-1 {
			out = append(out, ',')
		}
		out = append(out, '\n')
	}
	out = append(out, '}')
	return out, nil
}

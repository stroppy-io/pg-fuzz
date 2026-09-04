// Package census groups crash reports into distinct signatures.
//
// Hundreds of artifacts usually collapse into a handful of signatures, and a
// handful of signatures into fewer real defects. The grouping is the first
// step of triage and the only one a machine can do.
//
// WHAT THE SIGNATURE KEEPS, AND WHAT IT THROWS AWAY
// =================================================
// Everything that varies per hit goes: the pid, the address, the operand
// values. What stays is the predicate, the file basename and the line. Keeping
// a digit that changes on every hit turns one defect into a thousand
// signatures; dropping one that identifies the site merges two defects into
// one.
//
// THE LEAK RULE IS SEPARATE, AND THAT COST A CAMPAIGN
// ===================================================
// The ASan rule expects "SUMMARY: AddressSanitizer: <kind> ...", and a leak
// emits "SUMMARY: AddressSanitizer: 32768 byte(s) leaked in 4 allocation(s)"
// -- a digit where the kind should be. The consequence was not a mangled
// signature but NO signature: a campaign whose most interesting result was
// fifteen distinct leak sites consolidated to zero leak rows, in the directory
// kept precisely to preserve them. Leaks are keyed on the DEDUP_TOKEN's last
// frame, which is the allocation site and the only stable part.
//
// And deliberately NO second rule matching "byte(s) leaked": libFuzzer prints
// a DEDUP_TOKEN beside every leak it surfaces, so a SUMMARY rule matches the
// same report twice. It produced four phantom "unattributed" hits against four
// real ones when tried.
package census

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Row is one distinct signature.
type Row struct {
	Signature  string   `json:"signature"`
	Hits       int      `json:"hits"`
	Workspaces []string `json:"workspaces"`
	Families   []string `json:"families"`
	Targets    []string `json:"targets"`
	OrioleOnly bool     `json:"oriole_only"`
	OrioleWS   []string `json:"oriole_ws"`
	VanillaWS  []string `json:"vanilla_ws"`
	InOrioleDB bool     `json:"in_orioledb_code"`
	Sources    []string `json:"sources"`

	// How the signature's workspaces split by sanitizer. The summary table
	// has always shown these two columns and computed them on the way past;
	// the JSON did not carry them, so every consumer had to reimplement the
	// classification -- and any that did it from the workspace NAME got the
	// same wrong answer described on Annotate.
	ASan  int `json:"asan_ws"`
	UBSan int `json:"ubsan_ws"`
}

var (
	reAssert = regexp.MustCompile(`TRAP: failed Assert\("(.*?)"\), File: "(.*?)", Line: (\d+)`)
	reUB     = regexp.MustCompile(`(\S+\.[ch]):(\d+):\d+: (runtime error: [^\n]*)`)
	reASan   = regexp.MustCompile(`SUMMARY: AddressSanitizer: ([a-z\-]+) (\S+) in (\S+)`)
	reLF     = regexp.MustCompile(`ERROR: libFuzzer: (out-of-memory|timeout)`)
	reLeak   = regexp.MustCompile(`(?m)^DEDUP_TOKEN: \S*?--([A-Za-z_][A-Za-z0-9_]*)\s*$`)
	rePanic  = regexp.MustCompile(`(PANIC|FATAL):\s+(.{0,80})`)
	reDigits = regexp.MustCompile(`\d+`)
)

type hit struct{ sig, src string }

// leakScope tracks whether the lines going past belong to a LEAK report.
//
// WHY IT HAS TO EXIST. A DEDUP_TOKEN line is emitted by LeakSanitizer AND by
// UndefinedBehaviorSanitizer, and the two are structurally identical:
//
//	DEDUP_TOKEN: ___interceptor_malloc--AllocSetContextCreateInternal--CreateExecutorState
//	DEDUP_TOKEN: do_to_timestamp--to_date--DirectFunctionCall2Coll
//
// The first is a leak, the second is a UB site. Nothing in the token says
// which. Extract sees one line at a time, so it called every one of them a
// leak -- which double-counted every UBSan report (once correctly as UBSAN,
// once as a phantom LEAK) and invented leaks in undefined builds, where the
// sanitizer that finds leaks is not even linked.
//
// The enclosing report is the only evidence, so the reader carries it: a leak
// block opens with "LeakSanitizer: detected memory leaks" and holds until its
// SUMMARY, and a "runtime error:" line means UBSan has taken over.
type leakScope struct{ in bool }

// see updates the scope from a line and reports whether a DEDUP_TOKEN on this
// line should be read as a leak.
func (l *leakScope) see(line string) bool {
	switch {
	case strings.Contains(line, "LeakSanitizer: detected memory leaks"):
		l.in = true
	case strings.Contains(line, "runtime error:"):
		// UBSan's report; anything it dedups is not a leak.
		l.in = false
	case strings.HasPrefix(strings.TrimSpace(line), "SUMMARY:"):
		// A leak block is closed by its summary. Read the summary first, so
		// the tokens that preceded it still counted.
		defer func() { l.in = false }()
	}
	return l.in
}

// Extract pulls every signature out of one log's text.
func Extract(text string) []struct{ Sig, Src string } {
	var out []struct{ Sig, Src string }
	add := func(sig, src string) { out = append(out, struct{ Sig, Src string }{sig, src}) }

	for _, m := range reAssert.FindAllStringSubmatch(text, -1) {
		add("Assert("+m[1]+") "+filepath.Base(m[2])+":"+m[3], m[2])
	}
	for _, m := range reUB.FindAllStringSubmatch(text, -1) {
		// Operands differ on every hit, so digits collapse to N -- otherwise
		// one site becomes a thousand signatures.
		msg := reDigits.ReplaceAllString(m[3], "N")
		if len(msg) > 90 {
			msg = msg[:90]
		}
		add("UBSAN "+filepath.Base(m[1])+":"+m[2]+" "+msg, m[1])
	}
	for _, m := range reASan.FindAllStringSubmatch(text, -1) {
		add("ASAN "+m[1]+" "+filepath.Base(m[2])+" in "+m[3], m[2])
	}
	for _, m := range reLF.FindAllStringSubmatch(text, -1) {
		add("libFuzzer "+m[1], "")
	}
	// The leak rule is NOT here: a DEDUP_TOKEN alone cannot say whether it
	// came from LeakSanitizer or UBSan. ExtractLeak applies it once the
	// reader has established which report is open.
	for _, m := range rePanic.FindAllStringSubmatch(text, -1) {
		add(m[1]+" "+strings.TrimSpace(m[2]), "")
	}
	return out
}

// ExtractLeak pulls a leak signature from a DEDUP_TOKEN line, for a caller
// that has established the line sits inside a LeakSanitizer report.
func ExtractLeak(text string) (string, bool) {
	m := reLeak.FindStringSubmatch(text)
	if m == nil {
		return "", false
	}
	return "LEAK in " + m[1], true
}

// reBanner is the per-target banner a sweep log carries.
var reBanner = regexp.MustCompile(`^-{4} ([a-z_0-9]+_fuzzer) -{4}\s*$`)

// AddReader streams a log rather than reading it whole.
//
// Not os.ReadFile: three workspaces here hold 8.1 GB of sweep logs between
// them, and slurping one is how a census turns into an out-of-memory kill.
// Signatures are line-oriented except the assert, which fits on one line
// anyway, so a scanner sees everything a whole-file match would.
//
// The banner is tracked as it passes, so each signature is attributed to the
// target that was running when it appeared.
func (b *Builder) AddReader(workspace string, r io.Reader) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 256*1024), 8*1024*1024)
	var scope leakScope
	target := ""
	for sc.Scan() {
		raw := sc.Bytes()
		if !interesting(raw) {
			continue
		}
		line := sc.Text()
		if m := reBanner.FindStringSubmatch(line); m != nil {
			target = m[1]
			continue
		}
		inLeak := scope.see(line)
		for _, h := range Extract(line) {
			b.record(workspace, target, h.Sig, h.Src)
		}
		if inLeak {
			if sig, ok := ExtractLeak(line); ok {
				b.record(workspace, target, sig, "")
			}
		}
	}
	return sc.Err()
}

// markers are the byte sequences every signature regex REQUIRES.
//
// A line with none of them cannot match any of them, so skipping it changes no
// result. These logs are gigabytes of libFuzzer progress lines and six regexes
// over every one of them is most of the run time; grep is fast for exactly
// this reason -- it rejects almost everything before doing real work.
//
// Each entry is a literal the corresponding pattern cannot match without:
//
//	TRAP:               the assert form
//	runtime error:      UBSan
//	AddressSanitizer    ASan summaries
//	libFuzzer           out-of-memory and timeout
//	DEDUP_TOKEN         the leak form
//	PANIC: / FATAL:     the server's own
//	_fuzzer -           the target banner
var markers = [][]byte{
	[]byte("TRAP:"), []byte("runtime error:"), []byte("AddressSanitizer"),
	[]byte("libFuzzer"), []byte("DEDUP_TOKEN"), []byte("PANIC:"),
	[]byte("FATAL:"), []byte("_fuzzer -"),
}

func interesting(line []byte) bool {
	for _, m := range markers {
		if bytes.Contains(line, m) {
			return true
		}
	}
	return false
}

// AddSweep records a log that holds MANY targets, one after another.
//
// The matrix driver writes one log per round rather than one per target, so a
// whole-file Add attributes every signature in it to whichever target the
// filename suggests -- which for a sweep log is none of them. Splitting on the
// banner keeps the attribution the census exists to provide.
func (b *Builder) AddSweep(workspace, text string) {
	idx := reBanner.FindAllStringSubmatchIndex(text, -1)
	if len(idx) == 0 {
		b.Add(workspace, "", text)
		return
	}
	for i, m := range idx {
		target := text[m[2]:m[3]]
		end := len(text)
		if i+1 < len(idx) {
			end = idx[i+1][0]
		}
		b.Add(workspace, target, text[m[1]:end])
	}
}

// Builder accumulates signatures across workspaces.
type Builder struct {
	perWS   map[string]map[string]int
	targets map[string]map[string]bool
	sources map[string]map[string]bool
	units   map[[2]string]int
}

// New starts a census.
func New() *Builder {
	return &Builder{
		perWS:   map[string]map[string]int{},
		targets: map[string]map[string]bool{},
		sources: map[string]map[string]bool{},
	}
}

// Add records one log's signatures.
func (b *Builder) Add(workspace, target, text string) {
	for _, h := range Extract(text) {
		b.record(workspace, target, h.Sig, h.Src)
	}
}

func (b *Builder) record(workspace, target, sig, src string) {
	if b.perWS[sig] == nil {
		b.perWS[sig] = map[string]int{}
		b.targets[sig] = map[string]bool{}
		b.sources[sig] = map[string]bool{}
	}
	b.perWS[sig][workspace]++
	if target != "" {
		b.targets[sig][target] = true
	}
	if src != "" {
		b.sources[sig][src] = true
	}
}

// Rows returns the census, busiest first.
func (b *Builder) Rows() []Row {
	var out []Row
	for sig, per := range b.perWS {
		r := Row{Signature: sig}
		fams := map[string]bool{}
		for ws, n := range per {
			r.Hits += n
			r.Workspaces = append(r.Workspaces, ws)
			fams[Family(ws)] = true
			// THE DIFFERENTIAL THAT MATTERS. A signature seen only on oriole*
			// workspaces is OrioleDB's, because every oriole ref is a patched
			// PostgreSQL of the same major being fuzzed vanilla right beside
			// it. Seen on both, it is PostgreSQL's.
			if strings.HasPrefix(ws, "oriole") {
				r.OrioleWS = append(r.OrioleWS, ws)
			} else {
				r.VanillaWS = append(r.VanillaWS, ws)
			}
		}
		r.OrioleOnly = len(r.OrioleWS) > 0 && len(r.VanillaWS) == 0
		for t := range b.targets[sig] {
			r.Targets = append(r.Targets, t)
		}
		for s := range b.sources[sig] {
			r.Sources = append(r.Sources, s)
			// Failing INSIDE OrioleDB's tree is the strong signal.
			// Found-only-on-oriole is weak: fuzzing is random, so a rare
			// PostgreSQL defect lands on whichever workspace got there first.
			if strings.Contains(s, "orioledb") {
				r.InOrioleDB = true
			}
		}
		for f := range fams {
			r.Families = append(r.Families, f)
		}
		sort.Strings(r.Workspaces)
		sort.Strings(r.Families)
		sort.Strings(r.Targets)
		sort.Strings(r.OrioleWS)
		sort.Strings(r.VanillaWS)
		sort.Strings(r.Sources)
		if len(r.Sources) > 4 {
			r.Sources = r.Sources[:4]
		}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Hits != out[j].Hits {
			return out[i].Hits > out[j].Hits
		}
		return out[i].Signature < out[j].Signature
	})
	return out
}

// Write emits census/signatures.json under dir.
// Write records the census. known maps a workspace to its recorded sanitizer,
// so the JSON carries the same split the summary table shows; pass nil and the
// classification falls back to the name suffix, which is right for about half
// the workspaces on this host.
func (b *Builder) Write(dir string, known map[string]string) error {
	if err := os.MkdirAll(filepath.Join(dir, "census"), 0o755); err != nil {
		return err
	}
	rows := b.Rows()
	Annotate(rows, known)
	raw, err := json.MarshalIndent(rows, "", " ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "census", "signatures.json"),
		append(raw, '\n'), 0o644)
}

var reFamily = regexp.MustCompile(`^([a-z]+\d+)`)

// Family is the major-version group a workspace belongs to.
func Family(ws string) string {
	if m := reFamily.FindStringSubmatch(ws); m != nil {
		return m[1]
	}
	if i := strings.IndexAny(ws, "-"); i > 0 {
		return ws[:i]
	}
	return ws
}

// AddReaderAs streams a log that belongs to one known target.
func (b *Builder) AddReaderAs(workspace, target string, r io.Reader) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 256*1024), 8*1024*1024)
	var scope leakScope
	for sc.Scan() {
		line := sc.Text()
		inLeak := scope.see(line)
		for _, h := range Extract(line) {
			b.record(workspace, target, h.Sig, h.Src)
		}
		if inLeak {
			if sig, ok := ExtractLeak(line); ok {
				b.record(workspace, target, sig, "")
			}
		}
	}
	return sc.Err()
}

// EXECUTED UNITS AND ARTIFACTS, alongside the signatures.
//
// A target that executed zero units in every workspace contributed nothing to
// the campaign, and that is INVISIBLE in the reproducer counts -- a dead
// target files no crashes and so looks like a quiet one. The signature list
// alone cannot say which of the two a silent target is.

var reUnitsCensus = regexp.MustCompile(`stat::number_of_executed_units:\s+(\d+)`)

// Units is per (workspace, target) executed units, accumulated as logs are
// added.
func (b *Builder) Units() map[[2]string]int { return b.units }

// CountUnits records the executed units in one log.
func (b *Builder) CountUnits(workspace, target, text string) {
	if b.units == nil {
		b.units = map[[2]string]int{}
	}
	// Summed across the workers of one target: each prints its own line, and
	// the question is how much the TARGET did.
	for _, m := range reUnitsCensus.FindAllStringSubmatch(text, -1) {
		n, err := strconv.Atoi(m[1])
		if err == nil {
			b.units[[2]string{workspace, target}] += n
		}
	}
	// Recorded even at zero, so "ran and executed nothing" is distinguishable
	// from "never ran".
	if _, ok := b.units[[2]string{workspace, target}]; !ok {
		b.units[[2]string{workspace, target}] = 0
	}
}

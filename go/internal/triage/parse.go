package triage

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Finding is one write-up, as the record states it.
type Finding struct {
	Name, Area, Title string
	Status, FoundBy   string
	Found, Where      string
	Affects, Build    string
	Severity          string
	Cause             string
	CauseStated       bool
	Repro, ReproSrc   string
	SQLBlocks         int
	Inputs            []string
	Override          *[2]string
	Fixed, Confirmed  bool
	Warns             []string
}

var field = map[string]*regexp.Regexp{
	"status":   regexp.MustCompile(`(?m)^\*\*Status:?\*?\*?:?\s*(.+)`),
	"found_by": regexp.MustCompile(`(?m)^\*\*Found by:\*\*\s*(.+)`),
	"found":    regexp.MustCompile(`(?m)^\*\*Found:\*\*\s*(.+)`),
	"where":    regexp.MustCompile(`(?m)^\*\*(?:Where|Component):\*\*\s*(.+)`),
	"affects":  regexp.MustCompile(`(?m)^\*\*Affects:\*\*\s*(.+)`),
	"build":    regexp.MustCompile(`(?m)^\*\*Build:\*\*\s*(.+)`),
	"severity": regexp.MustCompile(`(?m)^\*\*Severity:\*\*\s*(.+)`),
	// AUTHORITATIVE when present, including when it says the cause is not
	// established. Heading-scraping below is the fallback for write-ups that
	// predate the field -- and it was wrong in both directions: it missed a
	// mechanism filed under "Why it deadlocks", and it would happily have
	// quoted a "Correction" section as a cause.
	"cause_field": regexp.MustCompile(`(?m)^\*\*Cause:\*\*\s*(.+)`),
}

// Headings that introduce a way to RUN the thing, and headings that introduce
// WHY it happens. The first match wins, so a write-up with both "Minimal
// reproducer" and a stray fenced block uses the former.
var (
	reproH = regexp.MustCompile(`(?im)^#{2,3}\s+((?:Minimal |Packaged )?Reproduc(?:e|er)\b.*|` +
		`Confirmed from SQL.*|The packaged reproducer.*)$`)
	causeH = regexp.MustCompile(`(?im)^#{2,3}\s+(Mechanism|The defect|Cause\b.*|Root cause|` +
		`The bug, in one line|What happens|The crash|The allocation|` +
		`Corrected summary.*|Summary|The measurement|The report|` +
		`What it was|The chain.*|What the assertion is actually guarding)$`)

	// A fenced block that is something to RUN. Prose fences carry output --
	// stack traces, ERROR lines, ASan reports -- and a blacklist of those never
	// finishes: the next write-up fences something new. So the test is
	// POSITIVE. A repro starts with a SQL statement or a shell command, and
	// anything that does not is output, however plausible it looks.
	runnable      = regexp.MustCompile("(?s)```(?:sql|bash|sh|console|c|text)?\n(.*?)```")
	runnableStart = regexp.MustCompile(`(?i)^\s*(?:\$\s*|#\s*)?(` +
		`SELECT|INSERT|UPDATE|DELETE|CREATE|ALTER|DROP|VACUUM|ANALYZE|` +
		`REINDEX|COPY|SET|BEGIN|DO|WITH|TRUNCATE|GRANT|EXPLAIN|` +
		`docker|psql|python3|\./|bash|sh\s|make|git|cd\s|export\s|` +
		`pg_ctl|initdb|postgres\s|pgbench|\./pgfuzz|ONLY=|PGFUZZ_|` +
		`[a-z_0-9]+=[#>]` +
		`)`)

	// psql transcripts are the clearest repro a write-up can carry and the
	// least copy-pasteable. Strip the prompt and keep the statement.
	promptRe = regexp.MustCompile(`(?im)^[a-z_0-9]+=[#>]\s?`)

	sqlStart = regexp.MustCompile(`(?i)^\s*(SELECT|INSERT|UPDATE|DELETE|CREATE|ALTER|DROP|VACUUM|ANALYZE|` +
		`REINDEX|COPY|SET|BEGIN|DO|WITH|TRUNCATE|GRANT|EXPLAIN)\b`)
	shellStart  = regexp.MustCompile(`(?i)^\s*(docker|psql|pg_ctl|initdb|postgres\s|pgbench)`)
	leadComment = regexp.MustCompile(`\A(?:\s*--[^\n]*\n)+`)
	leadAnyCmt  = regexp.MustCompile(`\A(?:\s*(?:--|#)[^\n]*\n)+`)
	nextHeading = regexp.MustCompile(`(?m)^#{1,3}\s+`)
	titleRe     = regexp.MustCompile(`\A#\s+(.+)`)
	sqlFence    = regexp.MustCompile("(?m)^```sql")
	starsRe     = regexp.MustCompile(`\*\*`)
	wsRe        = regexp.MustCompile(`\s+`)
)

// ReadWriteup returns README.md, or the whole write-up when asked.
//
// A finding is not always one file: oss-fuzz-harness-bugs keeps its per-defect
// reproduction recipes in DETAILS.md, and a rule that reads only README.md
// reports it as having no repro vector when it has fourteen.
func ReadWriteup(root, name string, siblings bool) string {
	d := filepath.Join(root, name)
	names := []string{"README.md"}
	if siblings {
		if ents, err := os.ReadDir(d); err == nil {
			var extra []string
			for _, e := range ents {
				if strings.HasSuffix(e.Name(), ".md") && e.Name() != "README.md" {
					extra = append(extra, e.Name())
				}
			}
			sort.Strings(extra)
			names = append(names, extra...)
		}
	}
	var out []string
	for _, f := range names {
		if b, err := os.ReadFile(filepath.Join(d, f)); err == nil {
			out = append(out, string(b))
		}
	}
	return strings.Join(out, "\n\n")
}

// sectionAfter is the body between a matching heading and the next heading of
// any level.
func sectionAfter(txt string, h *regexp.Regexp) string {
	m := h.FindStringIndex(txt)
	if m == nil {
		return ""
	}
	rest := txt[m[1]:]
	if n := nextHeading.FindStringIndex(rest); n != nil {
		return rest[:n[0]]
	}
	return rest
}

// vectorRank is how close a block is to the thing a maintainer wants to run.
//
// SQL FIRST, deliberately. A defect reachable from a statement should be
// reported as a statement -- the mchar crash is one SELECT, and offering a
// fuzzer invocation instead makes a two-line report look like it needs our
// tooling to see. Shell setup next. A harness call last: it is a real vector,
// and it is the one nobody outside this project can run.
func vectorRank(body string) int {
	body = leadComment.ReplaceAllString(body, "")
	if sqlStart.MatchString(body) {
		return 0
	}
	if shellStart.MatchString(body) {
		return 1
	}
	return 2
}

// ExtractRepro finds ONE vector. Not three, not a tour of the directory.
//
// Blocks are RANKED, not taken in document order, because write-ups lead with
// whichever form was found first and that is rarely the simplest. A finding
// whose write-up offers no runnable block and no file on disk has no repro
// vector, and saying so is the point -- that is the difference between
// something a maintainer can act on and a paragraph.
func ExtractRepro(root, txt, name string) (repro, src string) {
	for _, scope := range []struct{ Text, Label string }{
		{sectionAfter(txt, reproH), "stated"},
		{txt, "inferred"},
	} {
		if scope.Text == "" {
			continue
		}
		bestRank, bestBody := -1, ""
		for _, m := range runnable.FindAllStringSubmatch(scope.Text, -1) {
			body := promptRe.ReplaceAllString(strings.TrimSpace(m[1]), "")
			// A block that documents its preconditions in leading comments is
			// a BETTER repro, not a worse one -- credcheck's needs a
			// shared_preload_libraries line stated before the statement.
			probe := leadAnyCmt.ReplaceAllString(body, "")
			if body == "" || !runnableStart.MatchString(probe) {
				continue
			}
			r := vectorRank(body)
			if bestRank < 0 || r < bestRank {
				bestRank, bestBody = r, body
			}
			if r == 0 {
				break
			}
		}
		if bestRank >= 0 {
			lines := strings.Split(bestBody, "\n")
			if len(lines) > 12 {
				bestBody = strings.Join(lines[:12], "\n") + "\n..."
			}
			return bestBody, scope.Label
		}
	}
	// No block anywhere. A FILE on disk is still a vector -- checkpoint.sql is
	// as runnable as a fence, and refusing to name it would report the finding
	// as having nothing when it has something.
	for _, f := range InputsFor(root, name) {
		if strings.HasSuffix(f, ".sql") || strings.HasPrefix(filepath.Base(f), "repro") {
			return "psql -f " + f, "file"
		}
	}
	return "", ""
}

// FirstPara is the lead paragraph, and the next one when it introduces a block.
//
// Write-ups routinely end the sentence that explains the cause with a colon and
// then show the code. Stopping at the colon yields "converts the argument to
// pg_wchar form before matching:" -- a sentence that reads as truncated,
// because it is. So a paragraph ending in a colon pulls in the prose that
// follows, up to three paragraphs -- enough for the "X does A: <code> and that
// overflows B" shape, capped so a write-up of colon-led sections cannot pull in
// a whole section.
func FirstPara(body string) string {
	if strings.TrimSpace(body) == "" {
		return ""
	}
	var out []string
	for _, chunk := range regexp.MustCompile(`\n\s*\n`).Split(strings.TrimSpace(body), -1) {
		c := wsRe.ReplaceAllString(strings.TrimSpace(chunk), " ")
		if c == "" || strings.HasPrefix(c, "```") || strings.HasPrefix(c, "|") ||
			strings.HasPrefix(c, ">") {
			// A block is what the colon was introducing. Step OVER it and keep
			// looking for the prose that resumes the explanation; stopping
			// here is what produced the truncated sentences.
			if len(out) > 0 && strings.HasSuffix(out[len(out)-1], ":") {
				continue
			}
			if len(out) > 0 {
				break
			}
			continue
		}
		out = append(out, c)
		if !strings.HasSuffix(c, ":") || len(out) == 3 {
			break
		}
	}
	return strings.Join(out, " ")
}

// ParseFinding reads one write-up.
func ParseFinding(root, name string) Finding {
	txt := ReadWriteup(root, name, false)
	f := Finding{Name: name, Area: AreaOf(name), Title: name}
	if m := titleRe.FindStringSubmatch(txt); m != nil {
		f.Title = strings.TrimSpace(m[1])
	}
	get := func(k string) string {
		m := field[k].FindStringSubmatch(txt)
		if m == nil {
			return ""
		}
		return strings.Trim(starsRe.ReplaceAllString(strings.TrimSpace(m[1]), ""), " .*")
	}
	f.Status, f.FoundBy, f.Found = get("status"), get("found_by"), get("found")
	f.Where, f.Affects, f.Build = get("where"), get("affects"), get("build")
	f.Severity = get("severity")
	f.SQLBlocks = len(sqlFence.FindAllString(txt, -1))
	f.Inputs = InputsFor(root, name)
	if v, ok := AttribOverride[name]; ok {
		f.Override = &v
	}
	f.Repro, f.ReproSrc = ExtractRepro(root, txt, name)
	if f.Repro == "" {
		f.Repro, f.ReproSrc = ExtractRepro(root, ReadWriteup(root, name, true), name)
	}
	f.Cause = get("cause_field")
	f.CauseStated = f.Cause != ""
	if f.Cause == "" {
		f.Cause = FirstPara(sectionAfter(txt, causeH))
	}
	// A status the write-up asserts about ITSELF, in its own words.
	low := strings.ToLower(txt)
	f.Fixed = strings.Contains(low, "**fixed**") || strings.Contains(low, "fixed 2026")
	f.Confirmed = strings.Contains(strings.ToLower(f.Status), "confirmed") ||
		regexp.MustCompile(`(?i)\*\*Status:?\s*CONFIRMED`).MatchString(txt)
	for _, wrn := range []string{"CAUSE NOT ESTABLISHED", "ALMOST CERTAINLY WRONG",
		"SUPERSEDED", "not reported upstream"} {
		if strings.Contains(low, strings.ToLower(wrn)) {
			f.Warns = append(f.Warns, wrn)
		}
	}
	return f
}

// Evidence summarises what stands behind a finding.
func (f Finding) Evidence() string {
	switch {
	case f.Fixed:
		return "fixed"
	case f.Confirmed:
		return "confirmed"
	case len(f.Inputs) > 0 || f.SQLBlocks > 0:
		return "recorded"
	}
	return "no artefact"
}

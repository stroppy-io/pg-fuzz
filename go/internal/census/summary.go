package census

import (
	"fmt"
	"io"
	"sort"
	"strings"
)

// The consolidation summary: what a finished campaign found, from the run
// LOGS rather than from re-running reproducers.
//
// libFuzzer names each artifact after the sha1 of its input, so the same
// defect found by 24 workspaces gets 24 different names and name-based dedup
// tells you nothing. Signatures come from the logs.

// Liveness is one target's execution record across the campaign.
//
// A target that executed zero units in every workspace contributed nothing,
// and that is INVISIBLE in the reproducer counts -- a dead target files no
// crashes and so looks like a quiet one.
type Liveness struct {
	Target        string
	ExecutedUnits int
	WSSeen        int
	PerWS         map[string]int
	WSZeroUnits   []string
	Artifacts     int
}

// SummaryInput is everything the document needs.
type SummaryInput struct {
	Name       string
	Workspaces []string
	NLogs      int
	Artifacts  int
	Rows       []Row
	Live       []Liveness
	MatrixLog  string
	Provenance []Build
}

// Build is one workspace's resolved commit, as the campaign recorded it while
// each build landed.
type Build struct {
	Workspace, Ref, Sanitizer string
	PGSHA, OrioleDBSHA        string
	Patches                   string
}

// Sanitizer names the build a workspace is.
//
// FROM THE CONFIG WHERE THERE IS ONE. The suffix convention (-add, -und) is
// followed by half the workspaces on this host and by none of the ones any
// recent campaign created: 34 of 67 match it, while all 67 record sanitizer=
// in workspace.conf. Reading the name therefore answered "other" for every
// gt-* workspace that had in fact been built with AddressSanitizer, and the
// summary's asan and ubsan columns undercounted by half.
//
// known maps a workspace to its recorded sanitizer ("address", "undefined",
// "coverage"). The suffix remains the fallback for a workspace whose config
// cannot be read, which is the only case it was ever right about.
func Sanitizer(ws string, known map[string]string) string {
	switch known[ws] {
	case "address":
		return "asan"
	case "undefined":
		return "ubsan"
	case "coverage":
		return "coverage"
	}
	switch {
	case strings.HasSuffix(ws, "-add"):
		return "asan"
	case strings.HasSuffix(ws, "-und"):
		return "ubsan"
	}
	return "other"
}

// Annotate fills each row's sanitizer split, so the JSON carries what the
// summary table shows instead of leaving every consumer to recompute it.
func Annotate(rows []Row, known map[string]string) {
	for i := range rows {
		rows[i].ASan, rows[i].UBSan = 0, 0
		for _, w := range rows[i].Workspaces {
			switch Sanitizer(w, known) {
			case "asan":
				rows[i].ASan++
			case "ubsan":
				rows[i].UBSan++
			}
		}
	}
}

// WriteSummary renders the consolidation document.
func WriteSummary(out io.Writer, in SummaryInput) {
	var L []string
	a := func(f string, v ...any) {
		if len(v) == 0 {
			L = append(L, f)
			return
		}
		L = append(L, fmt.Sprintf(f, v...))
	}

	var dead []Liveness
	for _, r := range in.Live {
		if r.ExecutedUnits == 0 && r.WSSeen > 0 {
			dead = append(dead, r)
		}
	}

	a("# Campaign %s\n", in.Name)
	a("Consolidated by `pgfuzz census`. Numbers below come from the")
	a("run logs, not from re-running reproducers.\n")
	a("- workspaces: **%d**", len(in.Workspaces))
	a("- run logs scanned: **%d**", in.NLogs)
	a("- artifacts kept: **%d**", in.Artifacts)
	a("- distinct signatures: **%d**", len(in.Rows))
	if in.MatrixLog != "" {
		a("- campaign log: `logs/%s.gz`", in.MatrixLog)
	}
	a("")

	// WHICH COMMIT PRODUCED EACH SIGNATURE?
	//
	// Without this the directory records WHAT was found and not WHERE, and a
	// finding whose tree cannot be named is a finding that cannot be
	// rechecked. Most of this matrix builds from MOVING refs, so a workspace
	// name means a different tree every time a campaign rebuilds.
	//
	// Not a hypothetical worry: a 27-run differential once concluded
	// OrioleDB's fork leaked where upstream did not, and the two sides had
	// been built from code seventeen days apart. The difference was the
	// checkout date, not the fork.
	if len(in.Provenance) > 0 {
		a("## Builds these findings came from\n")
		a("Resolved commits, recorded as each build landed.")
		a("A signature below belongs to the tree named here, not to a version")
		a("number -- most of these refs move between campaigns.\n")
		a("| workspace | ref | san | postgres | orioledb | patches |")
		a("|---|---|---|---|---|---|")
		for _, r := range in.Provenance {
			a("| `%s` | `%s` | %s | `%s` | %s | %s |", r.Workspace, r.Ref,
				r.Sanitizer, r.PGSHA, codeOrDash(r.OrioleDBSHA), codeOrDash(strings.TrimSpace(r.Patches)))
		}
		a("")
	} else {
		a("> **No build provenance could be read.** These findings are not")
		a("> pinned to commits, so no signature below can be rechecked")
		a("> against the tree that produced it.\n")
	}

	if len(dead) > 0 {
		a("## Targets that executed nothing\n")
		a("These produced **zero** executed units. Whatever share of the")
		a("machine they were given was spent restarting a target that dies")
		a("before it fuzzes, and reproducer counts hide it completely.\n")
		a("| target | workspaces seen | workspaces at zero | artifacts |")
		a("|---|---|---|---|")
		for _, r := range dead {
			a("| `%s` | %d | %d | %d |", r.Target, r.WSSeen, len(r.WSZeroUnits), r.Artifacts)
		}
		a("")
	}

	a("## Signatures\n")
	a("`fams` is the set of major-version families the signature appeared in.")
	a("The same assert moves line number between majors, so a defect present")
	a("everywhere still shows up as several rows -- compare predicates, not")
	a("line numbers.\n")
	a("| hits | ws | asan | ubsan | families | targets | signature |")
	a("|---:|---:|---:|---:|---|---|---|")
	for _, r := range in.Rows {
		// Filled by Annotate, which the caller runs before writing either
		// document, so the table and the JSON cannot disagree.
		asan, ubsan := r.ASan, r.UBSan
		var short []string
		for _, t := range r.Targets {
			short = append(short, strings.TrimSuffix(t, "_fuzzer"))
		}
		a("| %d | %d | %d | %d | %s | %s | `%s` |", r.Hits, len(r.Workspaces),
			asan, ubsan, strings.Join(r.Families, " "), strings.Join(short, " "),
			strings.ReplaceAll(r.Signature, "|", "\\|"))
	}
	a("")

	a("## Executed units per target\n")
	a("| target | executed units | artifacts | ws at zero |")
	a("|---|---:|---:|---:|")
	for _, r := range in.Live {
		a("| `%s` | %s | %d | %d |", r.Target, commaN(r.ExecutedUnits),
			r.Artifacts, len(r.WSZeroUnits))
	}
	a("")
	io.WriteString(out, strings.Join(L, "\n"))
}

func codeOrDash(s string) string {
	if s == "" || s == "-" {
		return "&mdash;"
	}
	return "`" + s + "`"
}

func commaN(n int) string {
	s := fmt.Sprintf("%d", n)
	var b []byte
	for i := 0; i < len(s); i++ {
		if i > 0 && (len(s)-i)%3 == 0 {
			b = append(b, ',')
		}
		b = append(b, s[i])
	}
	return string(b)
}

// LivenessRows reduces per-(workspace,target) counts to one row per target.
//
// Per-workspace counts are KEPT, not only summed: the sum cannot express "dead
// on 8 workspaces, busy on 20", which is the case that hurts.
func LivenessRows(units, artifacts map[[2]string]int, workspaces []string) []Liveness {
	seenT := map[string]bool{}
	for k := range units {
		seenT[k[1]] = true
	}
	for k := range artifacts {
		seenT[k[1]] = true
	}
	var targets []string
	for t := range seenT {
		targets = append(targets, t)
	}
	sort.Strings(targets)

	var out []Liveness
	for _, t := range targets {
		r := Liveness{Target: t, PerWS: map[string]int{}}
		for _, w := range workspaces {
			u, hasU := units[[2]string{w, t}]
			_, hasA := artifacts[[2]string{w, t}]
			if !hasU && !hasA {
				continue
			}
			r.WSSeen++
			r.PerWS[w] = u
			r.ExecutedUnits += u
			if u == 0 {
				r.WSZeroUnits = append(r.WSZeroUnits, w)
			}
		}
		sort.Strings(r.WSZeroUnits)
		for k, v := range artifacts {
			if k[1] == t {
				r.Artifacts += v
			}
		}
		out = append(out, r)
	}
	// Quietest first: the targets that did nothing are the ones to read.
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].ExecutedUnits != out[j].ExecutedUnits {
			return out[i].ExecutedUnits < out[j].ExecutedUnits
		}
		return out[i].Target < out[j].Target
	})
	return out
}

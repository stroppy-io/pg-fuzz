package findings

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Reverification answers one question: DOES THE RECORD STILL HOLD.
//
// It is the check that keeps a findings directory honest, and the port had no
// equivalent at all -- `pgfuzz repro` takes one input against one workspace
// and has no notion of a finding, so the rules below had to be reconstructed
// by hand every time somebody wanted the answer.

// Vehicle is how a finding is re-checked.
type Vehicle int

const (
	// Unknown means the write-up does not say how, which is a SKIP and never
	// a pass.
	Unknown Vehicle = iota
	LibFuzzer
	SQL
	StorageScenario
)

func (v Vehicle) String() string {
	switch v {
	case LibFuzzer:
		return "libfuzzer"
	case SQL:
		return "sql"
	case StorageScenario:
		return "scenario"
	}
	return "unknown"
}

// Plan is what reverifying one finding requires.
type Plan struct {
	Finding   string
	Target    string
	Vehicle   Vehicle
	Workspace string
	// Artifacts is every input recorded for this finding, capped.
	//
	// ALL of them, not the first: a finding with 28 artifacts still holds if
	// ANY one of them reproduces, and taking only the first turns a finding
	// that reproduces one time in twenty-eight into "no longer reproduces".
	Artifacts []string
	// Skip is why this cannot be checked, when it cannot. A skip is never a
	// pass -- the whole point of naming it is that it is not one.
	Skip string
}

// MaxArtifacts bounds the work for one finding.
//
// Twelve, as the shell used. Unbounded would let a single finding with
// thousands of artifacts consume a reverification run; one would make the
// answer depend on which artifact happened to sort first.
const MaxArtifacts = 12

// PlanFor works out how to re-check a finding from its write-up.
//
// wsFor resolves a workspace name to a directory, and returns "" when the
// workspace named in the write-up no longer exists -- which is a SKIP with a
// reason, not a failure to reproduce.
func PlanFor(f Finding, dir string, wsFor func(string) string) Plan {
	// The target comes from "Found by:", which is where a write-up names the
	// fuzzer that produced it. That field is also what the report's
	// attribution column reads, so a finding with no origin recorded cannot be
	// re-checked either -- the two gaps are the same gap.
	p := Plan{Finding: f.Name, Target: TargetOf(f)}

	switch {
	case p.Target != "":
		p.Vehicle = LibFuzzer
	case hasFile(dir, "*.sql"):
		p.Vehicle = SQL
	case hasFile(dir, "seed*.json"):
		p.Vehicle = StorageScenario
	default:
		p.Skip = "the write-up does not say how to reproduce it"
		return p
	}

	// A WRITE-UP OFTEN DOES NOT NAME A WORKSPACE, and that is not a defect in
	// the write-up: a finding that affects "every major version tested" was
	// never about one workspace. The old reverify resolved by CAPABILITY --
	// any workspace that can run this target, preferring an -add build --
	// rather than requiring the record to name one. Naming one is honoured
	// when it is there.
	p.Workspace = wsFor(WorkspaceOf(f))
	if p.Workspace == "" {
		p.Skip = "no workspace on this host can run " + p.Target
		return p
	}

	if p.Vehicle == LibFuzzer {
		p.Artifacts = artifactsIn(dir)
		if len(p.Artifacts) == 0 {
			p.Skip = "no recorded artifact to run"
		}
	}
	return p
}

func hasFile(dir, glob string) bool {
	m, _ := filepath.Glob(filepath.Join(dir, glob))
	return len(m) > 0
}

// artifactsIn looks in the finding directory AND in reproducer/, which is
// where the write-ups on disk actually keep them. Looking only at the root
// found nothing for every finding in FINDINGS, and reported it as "no
// recorded artifact to run" -- a skip caused by the reader, not the record.
func artifactsIn(dir string) []string {
	var ents []os.DirEntry
	var bases []string
	for _, sub := range []string{"", "reproducer", "artifacts"} {
		d := filepath.Join(dir, sub)
		es, err := os.ReadDir(d)
		if err != nil {
			continue
		}
		for _, e := range es {
			ents = append(ents, e)
			bases = append(bases, d)
		}
	}
	var out []string
	for i, e := range ents {
		if e.IsDir() {
			continue
		}
		n := e.Name()
		if strings.HasPrefix(n, "crash-") || strings.HasPrefix(n, "leak-") ||
			strings.HasPrefix(n, "timeout-") || strings.HasPrefix(n, "oom-") {
			out = append(out, filepath.Join(bases[i], n))
		}
	}
	sort.Strings(out)
	if len(out) > MaxArtifacts {
		out = out[:MaxArtifacts]
	}
	return out
}

// Outcome is a reverification verdict.
type Outcome string

const (
	// StillReproduces means at least one artifact reproduced.
	StillReproduces Outcome = "still reproduces"
	// Gone means every artifact ran and none reproduced. This is the only
	// outcome that says the record no longer holds.
	Gone Outcome = "no longer reproduces"
	// Skipped means it could not be checked. NEVER a pass.
	Skipped Outcome = "skipped"
)

// TargetOf reads the fuzz target out of a finding's "Found by" line.
//
// The line is prose -- "protocol_fuzzer", "storage_fuzzer seed131", "source
// analysis" -- so the target is the first word that looks like one. Anything
// else leaves it empty, which routes the finding to a different vehicle or to
// an explicit skip rather than to a guess.
func TargetOf(f Finding) string {
	for _, w := range strings.Fields(f.FoundBy) {
		w = strings.Trim(w, "`*,.;:()[]")
		if strings.HasSuffix(w, "_fuzzer") {
			return w
		}
	}
	return ""
}

// WorkspaceOf reads the workspace a finding was recorded against.
//
// Written as "pg17-10-add" or similar inside the write-up. Empty when the
// write-up does not say, which is a skip with a reason.
func WorkspaceOf(f Finding) string {
	for _, w := range strings.Fields(f.FoundBy) {
		w = strings.Trim(w, "`*,.;:()[]")
		if reWorkspaceish.MatchString(w) {
			return w
		}
	}
	return ""
}

var reWorkspaceish = regexp.MustCompile(`^[a-z0-9]+[a-z0-9-]*-(add|und|cov|asan)$`)

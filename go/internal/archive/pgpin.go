package archive

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// PINNING POSTGRESQL, which the oss-fuzz pin already does for the substrate.
//
// A workspace naming `ref=origin/REL_17_STABLE` builds whatever that branch is
// TODAY. That is correct for a HEAD run and wrong for everything else: two
// campaigns a week apart are not comparable, and a finding recorded against
// "REL_17_STABLE" cannot be reproduced later because the name no longer means
// the same commit.
//
// The build already RESOLVES the branch and prints the sha. What was missing
// is a place to say "this campaign is against these commits" and a check that
// the tree still matches -- the same relationship oss-fuzz.pin has with the
// substrate.
//
// A MOVING BRANCH IS STILL ALLOWED. This does not forbid HEAD runs; it makes
// the difference explicit, so a run that meant to be pinned cannot silently
// drift and a run that meant to track HEAD is not pretending otherwise.

// PGPinFile is where the PostgreSQL pins live.
const PGPinFile = "project/postgres.pin"

// PGPin maps a ref to the commit it is pinned at.
type PGPin map[string]string

// ReadPGPin loads the pins, if there are any. A missing file means nothing is
// pinned, which is a valid state and not an error.
func ReadPGPin(repo string) (PGPin, error) {
	f, err := os.Open(filepath.Join(repo, PGPinFile))
	if err != nil {
		if os.IsNotExist(err) {
			return PGPin{}, nil
		}
		return nil, err
	}
	defer f.Close()

	p := PGPin{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		p[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return p, sc.Err()
}

// Write records the pins, sorted so a diff shows what moved rather than how
// the map happened to iterate.
func (p PGPin) Write(repo string) error {
	refs := make([]string, 0, len(p))
	for r := range p {
		refs = append(refs, r)
	}
	sort.Strings(refs)

	var b strings.Builder
	b.WriteString(`# The PostgreSQL commits this tree is pinned to.
#
# A workspace naming ref=origin/REL_17_STABLE builds whatever that branch is
# TODAY. Correct for a HEAD run, wrong for a comparison: two campaigns a week
# apart are not comparable, and a finding recorded against a branch NAME cannot
# be reproduced later, because the name no longer means the same commit.
#
# A ref listed here is checked before every build of it. A ref that is NOT
# listed still tracks its branch -- pinning is opt-in per ref, so a HEAD run
# stays possible and stays honest about being one.
#
# Update with: pgfuzz pin -pg <ref> [-reason "..."]

`)
	for _, r := range refs {
		fmt.Fprintf(&b, "%s=%s\n", r, p[r])
	}
	return os.WriteFile(filepath.Join(repo, PGPinFile), []byte(b.String()), 0o644)
}

// CheckPG reports whether a ref resolves to what it is pinned at.
//
// Returns "" when the ref is not pinned, which is not a failure: pinning is
// per ref, so an unpinned ref is a deliberate HEAD run.
func (p PGPin) Check(pgRepo, ref, resolved string) string {
	want, ok := p[ref]
	if !ok || want == "" {
		return ""
	}
	if want == resolved {
		return ""
	}
	return fmt.Sprintf(
		"%s is pinned to %s but resolves to %s.\n"+
			"  A pinned ref that has moved means this build is not the experiment the\n"+
			"  pin describes. Either check the tree out at the pin, or move the pin in\n"+
			"  a commit that says why -- every fingerprint after it will differ from\n"+
			"  every fingerprint before it, which is the point.",
		ref, short(want), short(resolved))
}

// ResolvePG is the commit a ref currently names.
func ResolvePG(pgRepo, ref string) (string, error) {
	out, err := exec.Command("git", "-C", pgRepo, "rev-parse", ref+"^{commit}").Output()
	if err != nil {
		return "", fmt.Errorf("cannot resolve %s in %s: %w", ref, pgRepo, err)
	}
	return strings.TrimSpace(string(out)), nil
}

func short(sha string) string {
	if len(sha) > 12 {
		return sha[:12]
	}
	return sha
}

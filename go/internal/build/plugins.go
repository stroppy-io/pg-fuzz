package build

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// Plugin is one row of plugins.tsv.
//
// The file is CONFIGURATION, not part of the tool -- which plugins at which
// version is the experiment, and it changes without this binary changing. What
// belongs here is the check that a row means what it says.
type Plugin struct {
	Name, Version, Repo, Ref string

	// The rest of the row. These are properties of the PLUGIN rather than of
	// any experiment -- what it needs to build, whether it has to be preloaded,
	// what CREATE EXTENSION wants -- and build.sh reads all three back out of
	// the manifest the export writes.
	Apt, Preload, Create string
}

// ReadPlugins parses the registry, skipping comments and blank lines.
func ReadPlugins(path string) ([]Plugin, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []Plugin
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) < 4 {
			continue
		}
		p := Plugin{Name: f[0], Version: f[1], Repo: f[2], Ref: f[3],
			Apt: "-", Preload: "no", Create: f[0]}
		if len(f) >= 7 {
			p.Apt, p.Preload, p.Create = f[4], f[5], f[6]
		}
		out = append(out, p)
	}
	return out, sc.Err()
}

// RefCheck is the verdict on one pin.
type RefCheck struct {
	Plugin
	OK          bool
	Unreachable bool
	Candidates  []string
}

// VerifyPlugins checks every ref in the registry actually exists.
//
// A registry pin is a guess until something checks it. Tag naming is not
// consistent across projects -- v3.0 vs v3.0.0, VERSION_4_16_3 vs 4.16.3,
// REL2_3_1 vs 2.3.1 -- so a version number given in a spec does not tell you
// the tag. Getting it wrong means a build that dies minutes in, or worse, a
// silent fallback to some other ref.
//
// `git ls-remote`, so it needs no clone and touches no workspace.
func VerifyPlugins(ctx context.Context, ps []Plugin, only []string) []RefCheck {
	want := map[string]bool{}
	for _, n := range only {
		want[n] = true
	}
	var out []RefCheck
	for _, p := range ps {
		if len(want) > 0 && !want[p.Name] {
			continue
		}
		c := RefCheck{Plugin: p}
		cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		b, err := exec.CommandContext(cctx, "git", "ls-remote", "--tags", "--heads", p.Repo).Output()
		cancel()
		if err != nil {
			c.Unreachable = true
			out = append(out, c)
			continue
		}
		refs := string(b)
		exact := regexp.MustCompile(`refs/(tags|heads)/` + regexp.QuoteMeta(p.Ref) + `(\^\{\})?\n`)
		c.OK = exact.MatchString(refs + "\n")
		if !c.OK {
			// Suggest the closest thing, since the usual cause is a naming
			// convention rather than a version that does not exist.
			c.Candidates = near(refs, p.Version)
		}
		out = append(out, c)
	}
	return out
}

var tagRe = regexp.MustCompile(`refs/tags/(\S+)`)

func near(refs, version string) []string {
	base := strings.ReplaceAll(strings.TrimPrefix(version, "v"), ".", "[._]")
	base = strings.ReplaceAll(base, "_", "[._]")
	re, err := regexp.Compile("(?i)" + base)
	if err != nil {
		return nil
	}
	var out []string
	for _, m := range tagRe.FindAllStringSubmatch(refs, -1) {
		t := m[1]
		if strings.HasSuffix(t, "^{}") || !re.MatchString(t) {
			continue
		}
		out = append(out, t)
		if len(out) == 3 {
			break
		}
	}
	return out
}

// FormatPluginChecks renders the verdicts and says how many were wrong.
func FormatPluginChecks(cs []RefCheck) (string, int) {
	var b strings.Builder
	fail := 0
	for _, c := range cs {
		fmt.Fprintf(&b, "  %-18s %-12s %-24s ", c.Name, c.Version, c.Ref)
		switch {
		case c.Unreachable:
			fmt.Fprintf(&b, "UNREACHABLE (%s)\n", c.Repo)
			fail++
		case c.OK:
			b.WriteString("ok\n")
		default:
			b.WriteString("MISSING\n")
			fail++
			for _, cand := range c.Candidates {
				fmt.Fprintf(&b, "  %-18s candidate: %s\n", "", cand)
			}
		}
	}
	if fail == 0 {
		fmt.Fprintf(&b, "\n  all %d ref(s) verified\n", len(cs))
	} else {
		fmt.Fprintf(&b, "\n  %d of %d ref(s) wrong -- fix plugins.tsv before building\n", fail, len(cs))
	}
	return b.String(), fail
}

package archive

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// The substrate this tree is built against, pinned.
//
// WHY A PIN AND NOT JUST A RECORD
// ===============================
// The manifest already RECORDS which oss-fuzz commit and which base image
// produced a run. That tells you afterwards that two runs are not comparable;
// it cannot give you back the substrate that produced the first one.
//
// Until this file existed, the clone was stable by ACCIDENT: bootstrap skipped
// the clone when one was already present, so nothing ever pulled and the
// commit stayed wherever it first landed. A fresh machine bootstrapping the
// same tree got a different substrate, a different fingerprint, and every
// comparison against the earlier runs silently crossed a line.
//
// That is the failure this project already has on record one layer down: a
// 27-run differential concluded OrioleDB's fork leaked where upstream did not,
// and the two arms had been built from code seventeen days apart. The
// difference was the checkout date, not the fork. A pin makes "these two runs
// are comparable" a precondition rather than an observation.
//
// MOVING THE PIN IS A DECISION, made in a commit that says why -- the same
// rule the ratchet applies to lowering a floor.
type Pin struct {
	Commit    string // the google/oss-fuzz commit to build against
	BaseImage string // repo@sha256:..., the form `docker pull` accepts
}

// PinFile is where it lives, beside the build recipe it constrains.
const PinFile = "project/oss-fuzz.pin"

// ReadPin loads the pin from a checkout.
func ReadPin(repo string) (Pin, error) {
	var p Pin
	b, err := os.ReadFile(filepath.Join(repo, PinFile))
	if err != nil {
		return p, err
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch strings.TrimSpace(k) {
		case "commit":
			p.Commit = strings.TrimSpace(v)
		case "base_image":
			p.BaseImage = strings.TrimSpace(v)
		}
	}
	if p.Commit == "" {
		return p, fmt.Errorf("%s names no commit", PinFile)
	}
	return p, nil
}

// Write saves a pin.
func (p Pin) Write(repo string) error {
	body := fmt.Sprintf(`# The substrate this tree is built against.
#
# Recorded is not the same as pinned. Without this file the oss-fuzz clone was
# whatever master happened to be on the day somebody bootstrapped, and two runs
# on two machines were not comparable however carefully everything else was
# controlled.
#
# Moving these is a decision. Change them in a commit that says why, and expect
# every fingerprint after it to differ from every fingerprint before it -- that
# is the point, and the campaign index will say so.
#
# Update with: pgfuzz pin -update -reason "..."

commit=%s
base_image=%s
`, p.Commit, p.BaseImage)
	return os.WriteFile(filepath.Join(repo, PinFile), []byte(body), 0o644)
}

// Mismatch is one way the substrate differs from the pin.
type Mismatch struct {
	What, Want, Got, Fix string
}

func (m Mismatch) String() string {
	return fmt.Sprintf("  %s\n    pinned:  %s\n    present: %s\n    fix:     %s",
		m.What, m.Want, orNone(m.Got), m.Fix)
}

func orNone(s string) string {
	if s == "" {
		return "(absent)"
	}
	return s
}

// Check compares the substrate on this machine against the pin.
//
// Returns every mismatch rather than the first: being told the commit is wrong,
// fixing it, and only then being told the image is wrong as well is two round
// trips for one answer.
func (p Pin) Check(ossfuzz string) []Mismatch {
	var out []Mismatch

	head := Commit(ossfuzz, false)
	if head != p.Commit {
		out = append(out, Mismatch{
			What: "oss-fuzz commit",
			Want: p.Commit, Got: head,
			Fix: fmt.Sprintf("git -C %s fetch origin && git -C %s checkout %s",
				ossfuzz, ossfuzz, p.Commit),
		})
	}
	// A DIRTY clone is a separate failure from a wrong commit, and worse: the
	// commit reads as correct while the tree is not what that commit says.
	if Dirty(ossfuzz) {
		out = append(out, Mismatch{
			What: "oss-fuzz clone has modified tracked files",
			Want: "clean", Got: "modified",
			Fix: fmt.Sprintf("git -C %s status && git -C %s checkout -- .", ossfuzz, ossfuzz),
		})
	}

	if p.BaseImage != "" {
		if got := localDigests(p.BaseImage); !contains(got, p.BaseImage) {
			out = append(out, Mismatch{
				What: "base image",
				Want: p.BaseImage, Got: strings.Join(got, " "),
				Fix: "docker pull " + p.BaseImage,
			})
		}
	}
	return out
}

// localDigests returns the repo digests docker holds for an image reference.
//
// The REPO digest, not the image ID: the id is local and cannot be pulled, so
// recording it would produce a pin nobody can act on.
//
// INSPECTED AS GIVEN. Stripping the reference back to its repository first
// asks docker about "repo" with no tag, which it resolves to :latest -- absent
// here -- so a pinned image that was present reported as missing, and the
// check told you to pull something you already had.
func localDigests(ref string) []string {
	out, err := exec.Command("docker", "inspect", "--format",
		"{{range .RepoDigests}}{{.}} {{end}}", ref).Output()
	if err != nil {
		return nil
	}
	return strings.Fields(string(out))
}

func contains(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

// CurrentPin reads what this machine actually has, for `pin -update`.
func CurrentPin(repo, ossfuzz string) (Pin, error) {
	p := Pin{Commit: Commit(ossfuzz, false)}
	if p.Commit == "unknown" {
		return p, fmt.Errorf("cannot read the oss-fuzz clone at %s", ossfuzz)
	}
	tag := DockerfileFrom(filepath.Join(repo, "project", "Dockerfile"))
	if tag == "" {
		return p, fmt.Errorf("no FROM line in project/Dockerfile")
	}
	if d := localDigests(tag); len(d) > 0 {
		p.BaseImage = d[0]
	} else {
		// Refused rather than left blank. A pin with no image is a pin that
		// silently stops covering half the substrate.
		return p, fmt.Errorf("docker holds no repo digest for %s -- pull it by digest first", tag)
	}
	return p, nil
}

// DockerfileFrom reads the FROM line, so the base image is taken from the
// recipe rather than assumed. Retagging upstream is then not a silent change.
func DockerfileFrom(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	for _, l := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(l, "FROM ") {
			if f := strings.Fields(l); len(f) > 1 {
				return f[1]
			}
		}
	}
	return ""
}

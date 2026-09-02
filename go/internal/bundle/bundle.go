// Package bundle packages a campaign into something somebody else can read.
//
// WHY IT IS A PIPELINE AND NOT A CHECKLIST
// ========================================
// The 2026-08-27 report was assembled by hand, one command at a time, and
// every manual step was somewhere a mistake could hide: coverage measured
// against a build two days stale, an archive eight files short that looked
// complete, a renderer reading a gather that predated the numbers it was
// rendering. Each was caught, but only because somebody was looking.
//
// So the ordering constraints are encoded rather than remembered:
//
//   - gather runs BEFORE render, always. Rendering alone reports whatever the
//     last gather saw, including coverage since superseded.
//   - the gates run FIRST and their verdict goes in the manifest. A bundle
//     built over a failing gate is still produced -- refusing would be worse,
//     you often want the evidence precisely when something is wrong -- but it
//     says so.
//   - every stage's status is checked. A stage that fails must not leave the
//     previous run's output in place to be packaged as fresh.
package bundle

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Stage is one step's outcome, recorded whether it passed or not.
type Stage struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

// Manifest is what the bundle says about itself.
//
// Including the stages that FAILED. A bundle that only records what worked is
// a bundle that looks complete when it is not, which is the specific failure
// this pipeline was written after.
type Manifest struct {
	Slug      string    `json:"slug"`
	RunID     string    `json:"run_id,omitempty"`
	Built     time.Time `json:"built"`
	Tool      string    `json:"tool"`
	Stages    []Stage   `json:"stages"`
	Files     []string  `json:"files"`
	GatesPass bool      `json:"gates_passed"`
}

// Add records a stage.
func (m *Manifest) Add(name string, ok bool, detail string) {
	m.Stages = append(m.Stages, Stage{Name: name, OK: ok, Detail: detail})
}

// Failed lists the stages that did not succeed.
func (m Manifest) Failed() []string {
	var out []string
	for _, s := range m.Stages {
		if !s.OK {
			out = append(out, s.Name)
		}
	}
	return out
}

// Write saves the manifest into the staged bundle.
func (m *Manifest) Write(stage string) error {
	m.Files = list(stage)
	b, err := json.MarshalIndent(m, "", " ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(stage, "MANIFEST.json"), append(b, '\n'), 0o644)
}

func list(root string) []string {
	var out []string
	filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		if rel != "MANIFEST.json" {
			out = append(out, rel)
		}
		return nil
	})
	return out
}

// CopyInto copies one file into the staged bundle under rel.
func CopyInto(stage, rel, src string) error {
	dst := filepath.Join(stage, rel)
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

// Archive writes the staged directory as one .tar.gz beside it.
//
// A folder AND an archive: the folder is browsable now, the archive is what
// survives being moved. Producing only one of them means somebody either
// cannot look at it or cannot send it.
func Archive(stage, out string) (int64, error) {
	f, err := os.Create(out)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)

	base := filepath.Base(stage)
	err = filepath.WalkDir(stage, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(stage, p)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		// Symlinks are followed nowhere: a bundle carrying a link into the
		// workspace it came from is one that stops resolving the moment it is
		// moved, which is the only thing an archive is for.
		if fi.Mode()&os.ModeSymlink != 0 {
			return nil
		}
		hdr, err := tar.FileInfoHeader(fi, "")
		if err != nil {
			return err
		}
		hdr.Name = filepath.Join(base, rel)
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		in, err := os.Open(p)
		if err != nil {
			return err
		}
		defer in.Close()
		_, err = io.Copy(tw, in)
		return err
	})
	if err != nil {
		tw.Close()
		gz.Close()
		return 0, err
	}
	if err := tw.Close(); err != nil {
		return 0, err
	}
	if err := gz.Close(); err != nil {
		return 0, err
	}
	fi, err := f.Stat()
	if err != nil {
		return 0, err
	}
	return fi.Size(), nil
}

// ArchiveDir writes one directory as a .tar.gz inside the staged bundle.
//
// Corpora are the expensive part of a bundle -- hundreds of megabytes -- and
// the reason they are archived rather than copied: a folder of two million
// tiny files is slow to copy, slow to move and slower to delete, and every
// one of them is already content-addressed so the tar loses nothing.
func ArchiveDir(stage, rel, src string) (int64, error) {
	dst := filepath.Join(stage, rel)
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return 0, err
	}
	f, err := os.Create(dst)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)

	var skipped int
	err = filepath.WalkDir(src, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // a corpus being written to loses entries; that is not fatal
		}
		relp, err := filepath.Rel(src, p)
		if err != nil || relp == "." {
			return nil
		}
		fi, err := d.Info()
		if err != nil {
			return nil
		}
		hdr, err := tar.FileInfoHeader(fi, "")
		if err != nil {
			return nil
		}
		hdr.Name = relp
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		in, err := os.Open(p)
		if err != nil {
			// Counted, not ignored: an unreadable corpus entry is the mode-600
			// root-owned case, and an archive quietly short of them is one
			// that looks complete.
			skipped++
			return nil
		}
		defer in.Close()
		_, err = io.Copy(tw, in)
		return err
	})
	tw.Close()
	gz.Close()
	if err != nil {
		return 0, err
	}
	if skipped > 0 {
		return 0, fmt.Errorf("%d corpus entries could not be read -- run `pgfuzz corpus -repair` first", skipped)
	}
	fi, err := f.Stat()
	if err != nil {
		return 0, err
	}
	return fi.Size(), nil
}

// Name is the directory a bundle lands in.
func Name(slug string, t time.Time) string {
	return fmt.Sprintf("%s-%s", slug, t.Format("20060102-150405"))
}

// Summary renders the manifest as text for the console.
func (m Manifest) Summary() string {
	var b strings.Builder
	for _, s := range m.Stages {
		mark := "ok  "
		if !s.OK {
			mark = "FAIL"
		}
		fmt.Fprintf(&b, "  %s %-14s %s\n", mark, s.Name, s.Detail)
	}
	return b.String()
}

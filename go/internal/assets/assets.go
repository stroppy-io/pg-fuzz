// Package assets carries the tool itself: the harnesses, our patches, the
// build recipe and the Dockerfile. It is what makes the binary self-sufficient
// -- somebody with this file and docker can build a workspace without our
// repository existing anywhere.
//
// WHAT IS IN HERE, AND WHAT IS DELIBERATELY NOT
// =============================================
// The test is: if it can change without the tool changing, it is config.
//
//	embedded    35 harness sources, add_fuzzers.diff, guc_file_nul.diff,
//	            main.diff, build.sh, Dockerfile, project.yaml -- ~320 KB, all
//	            written by this project
//	NOT         plugins.tsv (which plugins at which version is the experiment
//	            variable, and the file says so in its own header), the UBSan
//	            accept-list, workspace.conf, and a workspace's own patches, which are
//	            not ours to ship
//
// MATERIALISED, NOT SYMLINKED
// ===========================
// pgfuzz symlinks its project/ directory into the oss-fuzz clone. That is why
// its build path has to disable BuildKit: BuildKit hashes the symlink rather
// than the files behind it, so a COPY layer kept shipping stale patches after
// they changed on disk, and `docker rmi` did not clear it because the layer
// cache survives image removal. Writing real files removes the cause rather
// than working around it.
package assets

import (
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

//go:embed all:project
var content embed.FS

// Materialise writes the embedded project into dir, creating it if needed.
//
// Existing files are overwritten: the point is that the tree on disk matches
// the binary, and a leftover file from an older version is exactly the kind of
// difference that makes a build unreproducible.
func Materialise(dir string) error {
	return fs.WalkDir(content, "project", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel("project", p)
		if err != nil {
			return err
		}
		out := filepath.Join(dir, rel)
		if d.IsDir() {
			return os.MkdirAll(out, 0o755)
		}
		b, err := content.ReadFile(p)
		if err != nil {
			return err
		}
		mode := os.FileMode(0o644)
		if filepath.Ext(p) == ".sh" {
			mode = 0o755
		}
		if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
			return err
		}
		return os.WriteFile(out, b, mode)
	})
}

// Read returns one embedded file, for callers that want it without writing.
func Read(name string) ([]byte, error) {
	b, err := content.ReadFile(filepath.Join("project", name))
	if err != nil {
		return nil, fmt.Errorf("assets: %w", err)
	}
	return b, nil
}

// List names every embedded file, relative to the project root.
func List() ([]string, error) {
	var out []string
	err := fs.WalkDir(content, "project", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel("project", p)
		out = append(out, rel)
		return nil
	})
	return out, err
}

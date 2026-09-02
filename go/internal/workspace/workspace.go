// Package workspace reads a workspace's configuration -- the file that says
// which PostgreSQL, which sanitizer, which patches and which plugins an
// experiment is. It is configuration, not payload: the binary reads it, it is
// never embedded, and two people comparing results are comparing these files.
package workspace

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Conf is workspace.conf, parsed. Only the fields a reproduction needs are
// promoted; Raw keeps everything so nothing is silently dropped.
type Conf struct {
	Path      string // the workspace directory
	Name      string
	Project   string // OSS-Fuzz project name; per-workspace, so builds never collide
	Ref       string
	Sanitizer string
	Raw       map[string]string
}

// Get returns a key that was not promoted to a field.
func (c Conf) Get(k string) string { return c.Raw[k] }

// Load reads <dir>/workspace.conf.
//
// The format is key=value with # comments -- and the values legitimately
// contain '=' (a patch path, a GUC like cron.database_name='dbfuzz'), so the
// split is on the FIRST separator only. Splitting on all of them silently
// truncated gucs= when this was first written in shell.
func Load(dir string) (Conf, error) {
	p := filepath.Join(dir, "workspace.conf")
	f, err := os.Open(p)
	if err != nil {
		return Conf{}, fmt.Errorf("no workspace at %s: %w", dir, err)
	}
	defer f.Close()

	c := Conf{Path: dir, Name: filepath.Base(dir), Raw: map[string]string{}}
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 0, 64*1024), 4*1024*1024) // plugins= and patch= get long
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		c.Raw[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	if err := s.Err(); err != nil {
		return Conf{}, err
	}

	c.Project = c.Raw["project"]
	if c.Project == "" {
		// The same fallback pgfuzz uses, so a hand-written conf still works.
		c.Project = "pgfuzz-" + c.Name
	}
	c.Ref = c.Raw["ref"]
	c.Sanitizer = c.Raw["sanitizer"]
	return c, nil
}

// BaseOSVersion reads project.yaml's base_os_version, which decides the
// base-runner image tag.
//
// Scanned rather than parsed as YAML on purpose: one scalar field is not worth
// a dependency in a binary whose reason for existing is that somebody else can
// build and run it without a module proxy. If this ever needs a second field
// with any structure, take the dependency then.
func BaseOSVersion(ossFuzz, project string) string {
	const def = "ubuntu-24-04"
	f, err := os.Open(filepath.Join(ossFuzz, "projects", project, "project.yaml"))
	if err != nil {
		return def
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if v, ok := strings.CutPrefix(line, "base_os_version:"); ok {
			v = strings.TrimSpace(v)
			v = strings.Trim(v, `"'`)
			if v != "" && v != "legacy" {
				return v
			}
		}
	}
	return def
}

// Set writes one key to workspace.conf, replacing any existing value.
//
// Rewrites the whole file through a temporary and renames, so a reader never
// sees a half-written config -- a build and a status command run concurrently
// on the same workspace routinely, and a truncated conf reads as a workspace
// with no ref, no sanitizer and no key.
func Set(dir, key, value string) error {
	p := filepath.Join(dir, "workspace.conf")
	var keep []string
	if b, err := os.ReadFile(p); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			k, _, ok := strings.Cut(line, "=")
			if ok && strings.TrimSpace(k) == key {
				continue
			}
			keep = append(keep, line)
		}
	}
	// Drop a trailing empty line so the file does not grow one per write.
	for len(keep) > 0 && strings.TrimSpace(keep[len(keep)-1]) == "" {
		keep = keep[:len(keep)-1]
	}
	keep = append(keep, key+"="+value)

	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, []byte(strings.Join(keep, "\n")+"\n"), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// Key is the build key: ref, sanitizer and engine, with slashes flattened so
// a branch name like origin/master is a usable directory name.
func Key(ref, sanitizer, engine string) string {
	return strings.ReplaceAll(ref, "/", "-") + "__" + sanitizer + "__" + engine
}

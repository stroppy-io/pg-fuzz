// Package build turns a workspace configuration into built fuzz targets.
//
// It is the step that makes the binary self-sufficient: with it, somebody who
// has this file, docker and git can go from a workspace.conf to a tree they
// can reproduce a finding against. Without it they can only replay an input
// against a build somebody else made.
//
// WHAT IT DOES NOT DO
// ===================
// Compile anything itself. PostgreSQL is built inside the OSS-Fuzz builder
// image by project/build.sh, exactly as before -- that script is the build
// recipe and is embedded rather than reimplemented. This package resolves the
// ref, exports the source, materialises the project, and drives the two
// container steps.
package build

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"pgfuzz/internal/assets"
	"pgfuzz/internal/workspace"
)

// Request is one build.
type Request struct {
	OSSFuzz   string // the oss-fuzz clone
	Project   string // OSS-Fuzz project name, per workspace
	SrcDir    string // exported PostgreSQL tree, bind-mounted into the build
	OutDir    string // where helper.py leaves the built targets
	Sanitizer string
	Engine    string
	Env       map[string]string // PGFUZZ_* knobs read by build.sh
	Plugins   string            // path to plugins.tsv, or "" for none
	Stream    io.Writer
	Timeout   time.Duration

	// LogDir is where the build log and its timing are written.
	//
	// The shell kept <ws>/builds/<key>.log -- the whole helper.py output --
	// and <ws>/builds/<key>.buildtime.json, which it read back to estimate the
	// next build. The port buffers the output in memory, re-prints only the
	// lines matching error:|undefined reference|FAILED on failure, and lets
	// the rest die with the process. So "why did this build fail" is
	// answerable only if somebody was watching, and "how long does a cold
	// build take here" -- the question the JSON was added for -- became
	// unanswerable again.
	//
	// Empty means do not write one, which keeps the library usable from a
	// test.
	LogDir string
	// LogKey names the log, normally the workspace's build key.
	LogKey string
}

// Result is what the build produced.
type Result struct {
	Elapsed time.Duration
	Targets []string
	Log     string
	// LogPath is where the log was kept, or "". Named on failure so the
	// reader is sent somewhere rather than told to have been watching.
	LogPath string
}

// Prepare materialises the embedded project into the oss-fuzz clone.
//
// Real files, not a symlink. pgfuzz symlinks its project directory here and
// has to disable BuildKit because of it: BuildKit hashes the symlink rather
// than the files behind it, so COPY layers kept shipping stale patches after
// they changed, and image removal did not clear the layer cache. Writing files
// removes the cause.
//
// plugins.tsv is copied in separately because it is configuration -- which
// plugins at which version is the experiment -- and must not be baked into the
// binary.
func Prepare(ossFuzz, project, pluginsTSV string) error {
	// THE OUTPUT PATH, cleared of whatever the last build left pointing at it.
	//
	// A finished build is moved into its destination and a symlink left here in
	// its place. When that destination is later removed -- a campaign directory
	// deleted, a workspace pruned -- the symlink is left DANGLING, and
	// helper.py's `os.makedirs(directory, exist_ok=True)` raises
	// FileExistsError on a path that exists and is not a directory. What the
	// user sees is a Python traceback out of OSS-Fuzz with no mention of a
	// symlink, on a workspace that built fine an hour earlier.
	out := filepath.Join(ossFuzz, "build", "out", project)
	if fi, err := os.Lstat(out); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 {
			if err := os.Remove(out); err != nil {
				return fmt.Errorf("removing stale build symlink %s: %w", out, err)
			}
		} else if fi.IsDir() {
			// A REAL DIRECTORY HERE IS LEFTOVER, and it has to go.
			//
			// The shell wiped this before every build. helper.py defaults to
			// clean=False and logs "Keeping existing build artifacts as-is",
			// and on the happy path the move below empties the directory --
			// so this only bites after a build that FAILED or was interrupted
			// part-way. Then the previous ref's binaries survive, the next
			// build inherits them, and Targets() lists them as this build's
			// output: a workspace reporting 23 targets of which several were
			// compiled from another commit.
			if err := os.RemoveAll(out); err != nil {
				return fmt.Errorf("clearing the previous build at %s: %w", out, err)
			}
		}
	}

	dir := filepath.Join(ossFuzz, "projects", project)
	// A previous run may have left a symlink here.
	if fi, err := os.Lstat(dir); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		if err := os.Remove(dir); err != nil {
			return fmt.Errorf("removing stale symlink %s: %w", dir, err)
		}
	}
	if err := assets.Materialise(dir); err != nil {
		return fmt.Errorf("writing project: %w", err)
	}
	if pluginsTSV != "" {
		b, err := os.ReadFile(pluginsTSV)
		if err != nil {
			return fmt.Errorf("plugins: %w", err)
		}
		if err := os.WriteFile(filepath.Join(dir, "plugins.tsv"), b, 0o644); err != nil {
			return err
		}
	}
	return nil
}

// Image builds the builder image.
func Image(ctx context.Context, r Request) error {
	// BuildKit off, as pgfuzz does. The symlink reason is gone now that the
	// project is materialised, but the legacy builder also keys its COPY cache
	// on file contents and keeps that cache in the image layers -- so a hard
	// reset is `docker rmi` and nothing else. Kept until there is a reason to
	// change it, because the assembly is seconds either way.
	cmd := exec.CommandContext(ctx, "python3", "infra/helper.py",
		"build_image", "--no-pull", r.Project)
	cmd.Dir = r.OSSFuzz
	cmd.Env = append(os.Environ(), "DOCKER_BUILDKIT=0")
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("image build failed: %w\n%s", err, tail(buf.String(), 20))
	}
	return nil
}

// Fuzzers runs the in-container build.
func Fuzzers(ctx context.Context, r Request) (Result, error) {
	if r.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, r.Timeout)
		defer cancel()
	}
	args := []string{"infra/helper.py", "build_fuzzers"}
	// build.sh runs inside the container and inherits nothing, so every knob
	// has to be passed explicitly. A silently dropped one produces a build
	// that looks like it honoured the setting, which invalidates whatever the
	// build was meant to prove.
	for _, k := range sortedKeys(r.Env) {
		args = append(args, "-e", k+"="+r.Env[k])
	}
	args = append(args, "--sanitizer", r.Sanitizer, "--engine", r.Engine,
		r.Project, r.SrcDir)

	cmd := exec.CommandContext(ctx, "python3", args...)
	cmd.Dir = r.OSSFuzz
	var buf bytes.Buffer
	var sink io.Writer = &buf
	if r.Stream != nil {
		sink = io.MultiWriter(&buf, r.Stream)
	}
	cmd.Stdout, cmd.Stderr = sink, sink

	start := time.Now()
	err := cmd.Run()
	res := Result{Elapsed: time.Since(start), Log: buf.String()}
	// WRITTEN WHETHER IT WORKED OR NOT. A failed build is the one whose log
	// somebody actually needs.
	res.LogPath = writeBuildLog(r, buf.Bytes(), res.Elapsed, err == nil)

	// The exit code alone is not enough: helper.py has returned 0 with no
	// output directory. What the next stage receives is the thing to check.
	if _, statErr := os.Stat(r.OutDir); err != nil || statErr != nil {
		where := ""
		if res.LogPath != "" {
			where = "\nfull log: " + res.LogPath
		}
		return res, fmt.Errorf("build failed: %v\n%s%s", err, interesting(buf.String()), where)
	}
	// Before listing the targets, not after: Targets looks for executable
	// files, so it doubles as the check that handing the tree back did not
	// strip the execute bit off the binaries.
	if err := Reown(ctx, "gcr.io/oss-fuzz/"+r.Project, r.OutDir); err != nil {
		return res, err
	}

	res.Targets, _ = Targets(r.OutDir)
	if len(res.Targets) == 0 {
		return res, fmt.Errorf("build produced no fuzz targets in %s", r.OutDir)
	}
	return res, nil
}

// Targets lists the built fuzz targets, the same way pgfuzz does: executable
// files ending in _fuzzer at the top of the output directory.
func Targets(out string) ([]string, error) {
	ents, err := os.ReadDir(out)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range ents {
		n := e.Name()
		if !strings.HasSuffix(n, "_fuzzer") {
			continue
		}
		fi, err := os.Stat(filepath.Join(out, n))
		if err != nil || fi.IsDir() || fi.Mode()&0o111 == 0 {
			continue
		}
		names = append(names, n)
	}
	return names, nil
}

// EnvFor collects the PGFUZZ_* knobs a workspace declares.
func EnvFor(c workspace.Conf) map[string]string {
	m := map[string]string{}
	for conf, env := range map[string]string{
		"extensions":          "PGFUZZ_EXTENSIONS",
		"extra_types":         "PGFUZZ_EXTRA_TYPES",
		"preload":             "PGFUZZ_PRELOAD",
		"disabled_extensions": "PGFUZZ_DISABLED_EXTENSIONS",
		"skip_schemas":        "PGFUZZ_SKIP_SCHEMAS",
		"gucs":                "PGFUZZ_GUCS",
	} {
		if v := c.Get(conf); v != "" {
			m[env] = v
		}
	}
	for _, k := range []string{"PGFUZZ_SERVER_ASAN", "PGFUZZ_SERVER_CASSERT"} {
		if v := os.Getenv(k); v != "" {
			m[k] = v
		}
	}
	return m
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

func tail(s string, n int) string {
	l := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(l) > n {
		l = l[len(l)-n:]
	}
	return strings.Join(l, "\n")
}

// writeBuildLog keeps the output and the timing beside the workspace.
//
// Errors are deliberately swallowed: a build that succeeded must not be
// reported as failed because its log could not be written, and the path it
// returns is empty when nothing was kept.
func writeBuildLog(r Request, out []byte, took time.Duration, ok bool) string {
	if r.LogDir == "" || r.LogKey == "" {
		return ""
	}
	if err := os.MkdirAll(r.LogDir, 0o755); err != nil {
		return ""
	}
	p := filepath.Join(r.LogDir, r.LogKey+".log")
	if err := os.WriteFile(p, out, 0o644); err != nil {
		return ""
	}
	// The timing, in a form something can read back. "How long does a cold
	// build take here" is the question this answers, and prose in a worklog
	// does not answer it.
	b, err := json.Marshal(struct {
		Key     string  `json:"key"`
		Seconds float64 `json:"seconds"`
		OK      bool    `json:"ok"`
		At      string  `json:"at"`
	}{r.LogKey, took.Seconds(), ok, time.Now().UTC().Format(time.RFC3339)})
	if err == nil {
		_ = os.WriteFile(filepath.Join(r.LogDir, r.LogKey+".buildtime.json"),
			append(b, '\n'), 0o644)
	}
	return p
}

// interesting pulls the lines a failed build is actually about.
func interesting(s string) string {
	var out []string
	seen := map[string]bool{}
	for _, l := range strings.Split(s, "\n") {
		if strings.Contains(l, "error:") || strings.Contains(l, "undefined reference") ||
			strings.Contains(l, "FAILED") {
			if !seen[l] {
				seen[l] = true
				out = append(out, l)
			}
		}
		if len(out) >= 20 {
			break
		}
	}
	if len(out) == 0 {
		return tail(s, 20)
	}
	return strings.Join(out, "\n")
}

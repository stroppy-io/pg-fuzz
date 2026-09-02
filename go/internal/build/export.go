package build

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// ExportPlugins fetches a workspace's out-of-tree extensions and puts them in
// the source export where build.sh expects them.
//
// THIS WAS MISSING FROM THE PORT, and it failed silently, which is the part
// worth remembering. `ws -new -plugins ...` recorded the list, `build` never
// read it, and the build SUCCEEDED -- 23 targets, exit 0, no warning -- with
// none of the twelve plugins in it. Nothing downstream could tell the
// difference between "this workspace has no plugins" and "this workspace's
// plugins were dropped on the floor", because the two produce the same build.
//
// Everything is fetched on the HOST, into $PGFUZZ_CACHE/plugins/<name>, and
// exported into <src>/plugins/<name>. helper.py bind-mounts one directory, so
// that is how source reaches build.sh; nothing is fetched inside the container,
// which is why a build stays reproducible and needs no network.
//
// Alongside the sources it writes what build.sh reads back:
//
//	plugins/MANIFEST.tsv   name, provenance sha, apt deps, preload, create name
//	plugins/APT-DEPS       build dependencies the image must install
//	plugins/PRELOAD        libraries that must be in shared_preload_libraries
func ExportPlugins(list string, registry []Plugin, cache, src string, out io.Writer) error {
	specs := strings.Fields(list)
	if len(specs) == 0 {
		return nil
	}
	dir := filepath.Join(src, "plugins")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(cache, 0o755); err != nil {
		return err
	}

	say := func(f string, a ...any) {
		if out != nil {
			fmt.Fprintf(out, "    "+f+"\n", a...)
		}
	}

	var rows, apts, preloads []string
	for _, spec := range specs {
		p, err := resolveSpec(spec, registry)
		if err != nil {
			return err
		}
		dst := filepath.Join(dir, p.Name)
		os.RemoveAll(dst)

		var prov string
		if fi, err := os.Stat(p.Repo); err == nil && fi.IsDir() {
			// A local working tree: copied as-is. Record WHICH tree, not just
			// "local" -- two editions can each say "local" and point at
			// different trees, and that is how a coverage build once spent two
			// days measuring stock orafce while the fuzzing builds ran the
			// patched one.
			prov = localProvenance(p.Repo)
			if err := copyTree(p.Repo, dst); err != nil {
				return fmt.Errorf("plugin %s: copying %s: %w", p.Name, p.Repo, err)
			}
			say("plugin %s <- %s (%s)", p.Name, p.Repo, prov)
		} else {
			sha, err := exportGit(p, cache, dst, out)
			if err != nil {
				return err
			}
			prov = sha
			say("plugin %s %s (%s) exported", p.Name, p.Ref, sha)
		}

		rows = append(rows, strings.Join([]string{p.Name, prov, p.Apt, p.Preload, p.Create}, "\t"))
		if p.Apt != "-" && p.Apt != "" {
			apts = append(apts, p.Apt)
		}
		if p.Preload == "yes" {
			preloads = append(preloads, p.Name)
		}
	}

	if err := os.WriteFile(filepath.Join(dir, "MANIFEST.tsv"),
		[]byte(strings.Join(rows, "\n")+"\n"), 0o644); err != nil {
		return err
	}
	if len(apts) > 0 {
		if err := os.WriteFile(filepath.Join(dir, "APT-DEPS"),
			[]byte(strings.Join(apts, " ")+"\n"), 0o644); err != nil {
			return err
		}
	}
	if len(preloads) > 0 {
		say("plugins needing shared_preload_libraries: %s", strings.Join(preloads, " "))
		if err := os.WriteFile(filepath.Join(dir, "PRELOAD"),
			[]byte(strings.Join(preloads, " ")+"\n"), 0o644); err != nil {
			return err
		}
	}
	return nil
}

// resolveSpec reads one entry of a workspace's plugins= line.
//
// Accepted forms, most specific wins:
//
//	name             registry repo, registry default ref
//	name@ref         registry repo, THIS workspace's ref -- the common case
//	name@url@ref     no registry involvement at all
//	name@/local/path a working tree on this host
func resolveSpec(spec string, registry []Plugin) (Plugin, error) {
	name, rest, _ := strings.Cut(spec, "@")
	p := Plugin{Name: name, Apt: "-", Preload: "no", Create: name}

	// Fully explicit: a URL or an absolute path, registry not consulted.
	if strings.Contains(rest, "://") || strings.HasPrefix(rest, "/") {
		repo, ref, ok := strings.Cut(rest, "@")
		// A URL contains no second @; a path may be given without a ref.
		if !ok {
			repo, ref = rest, "HEAD"
		}
		p.Repo, p.Ref = repo, ref
		return p, nil
	}

	for _, r := range registry {
		if r.Name == name {
			p = r
			if rest != "" {
				p.Ref = rest // the workspace pins the version
			}
			return p, nil
		}
	}
	return Plugin{}, fmt.Errorf("unknown plugin %q -- add it to project/plugins.tsv, "+
		"or give it inline as name@url@ref", name)
}

// localProvenance names a working tree precisely enough to compare two builds.
func localProvenance(dir string) string {
	if _, err := os.Stat(filepath.Join(dir, ".git")); err != nil {
		return "local"
	}
	sha, err := exec.Command("git", "-C", dir, "rev-parse", "--short", "HEAD").Output()
	if err != nil {
		return "local:unknown"
	}
	prov := "local:" + strings.TrimSpace(string(sha))
	if exec.Command("git", "-C", dir, "diff", "--quiet", "HEAD").Run() != nil {
		prov += "+dirty"
	}
	return prov
}

// exportGit clones into the cache if needed, then extracts one ref.
func exportGit(p Plugin, cache, dst string, out io.Writer) (string, error) {
	repo := filepath.Join(cache, p.Name)
	if _, err := os.Stat(filepath.Join(repo, ".git")); err != nil {
		os.RemoveAll(repo)
		if out != nil {
			fmt.Fprintf(out, "    plugin %s: cloning %s\n", p.Name, p.Repo)
		}
		c := exec.Command("git", "clone", "--quiet", p.Repo, repo)
		c.Stderr = out
		if err := c.Run(); err != nil {
			return "", fmt.Errorf("plugin %s: clone %s: %w", p.Name, p.Repo, err)
		}
	}
	// Refreshed unconditionally, so a moving ref means today's code.
	if err := exec.Command("git", "-C", repo, "fetch", "--tags", "--prune", "--quiet", "origin").Run(); err != nil && out != nil {
		fmt.Fprintf(out, "    plugin %s: fetch failed, using cached refs\n", p.Name)
	}
	// A BRANCH does not resolve by its bare name in a clone. `git rev-parse X`
	// looks in refs/heads, refs/tags and refs/remotes/X -- and a cloned
	// repository has the upstream's branches under refs/remotes/origin/X, so
	// only TAGS resolve bare. Every plugin here was pinned to a tag, which is
	// why this never showed until a workspace asked for pgaudit's per-major
	// branch and got `unknown ref "REL_18_STABLE"` for a branch that plainly
	// exists.
	ref := p.Ref
	shaOut, err := exec.Command("git", "-C", repo, "rev-parse", "--short", ref+"^{commit}").Output()
	if err != nil {
		ref = "origin/" + p.Ref
		shaOut, err = exec.Command("git", "-C", repo, "rev-parse", "--short", ref+"^{commit}").Output()
	}
	if err != nil {
		return "", fmt.Errorf("plugin %s: unknown ref %q (tried %q and %q)",
			p.Name, p.Ref, p.Ref, "origin/"+p.Ref)
	}
	sha := strings.TrimSpace(string(shaOut))

	if err := os.MkdirAll(dst, 0o755); err != nil {
		return "", err
	}
	// archive|tar rather than a worktree: it lands the ref's contents with no
	// .git, which is what gets bind-mounted into the build.
	ar := exec.Command("git", "-C", repo, "archive", ref)
	tr := exec.Command("tar", "-x", "-C", dst)
	pipe, err := ar.StdoutPipe()
	if err != nil {
		return "", err
	}
	tr.Stdin = pipe
	if err := ar.Start(); err != nil {
		return "", err
	}
	if err := tr.Run(); err != nil {
		return "", fmt.Errorf("plugin %s: extracting %s: %w", p.Name, ref, err)
	}
	if err := ar.Wait(); err != nil {
		return "", fmt.Errorf("plugin %s: archiving %s: %w", p.Name, ref, err)
	}
	return sha, nil
}

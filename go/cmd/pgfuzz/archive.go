package main

import (
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"pgfuzz/internal/archive"
	"pgfuzz/internal/campaign"
	"pgfuzz/internal/paths"
)

// cmdArchive freezes a finished campaign into a run directory.
//
// THE WRITER FOR A READER THAT SURVIVED. archive.NewManifest, TarCorpus,
// FuzzerHashes, ReproducerCounts, Builds and Fingerprint were all ported and
// none of them had a caller: there was no `archive` command and no mention of
// one in the usage. The READER is faithful -- `pgfuzz index` walks
// campaigns/<slug>/<run>/MANIFEST.json and renders the history page -- so the
// history was permanently frozen at whatever the deleted shell had written,
// and a new run could never appear on it.
//
// A RUN DIRECTORY IS WRITE-ONCE. The index page states this in its own lede:
// "it all comes from write-once archives, so a run that happened cannot be
// edited by a later one". Nothing enforced it. The seal is applied last, so
// everything above it -- the manifest, the corpus, the series -- is inside it.
func cmdArchive(argv []string) int {
	fs_ := flag.NewFlagSet("archive", flag.ExitOnError)
	slug := fs_.String("slug", "", "campaign to archive")
	noCorpus := fs_.Bool("no-corpus", false, "record the corpus count without archiving it")
	force := fs_.Bool("force", false, "archive even while the campaign is running")
	fs_.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	if err := fs_.Parse(argv); err != nil || *slug == "" {
		fs_.Usage()
		return 2
	}

	r := paths.Resolve()
	home, err := r.NeedHome()
	if err != nil {
		fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
		return 2
	}
	slugDir := filepath.Join(r.Campaigns(), *slug)
	if !fileExists(filepath.Join(slugDir, "MANIFEST.json")) &&
		!fileExists(filepath.Join(slugDir, "series.jsonl")) {
		fmt.Fprintf(os.Stderr, "pgfuzz: no campaign at %s\n", slugDir)
		return 2
	}

	// ARCHIVE A FINISHED ONE. An archive of a campaign still adding to itself
	// is an archive of nothing: the corpus it counts and the series it copies
	// both move while it works.
	if pid := campaign.LiveDriver(slugDir); pid > 0 && !*force {
		fmt.Fprintf(os.Stderr,
			"pgfuzz: %s is still running (pid %d) -- archive a FINISHED campaign,\n"+
				"  or pass -force and accept that the contents move while it copies\n",
			*slug, pid)
		return 2
	}

	man, err := campaign.ReadManifest(slugDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
		return 2
	}
	var wss []string
	for _, e := range man.Entries {
		if e.BuildOK {
			wss = append(wss, e.Workspace)
		}
	}

	fp, err := archive.Fingerprint(archive.FingerprintInputs{
		Repo: home, OSSFuzz: r.OSSFuzz(), WSRoot: r.WS,
		Workspaces: wss, BaseImage: man.BaseImage,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "pgfuzz: fingerprint: %v\n", err)
		return 2
	}

	stamp := time.Now().UTC().Format("20060102-150405")
	dest := filepath.Join(slugDir, *slug+"-"+stamp+"-"+fp)
	if err := os.MkdirAll(dest, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "pgfuzz: %v\n", err)
		return 2
	}
	fmt.Printf("archiving %s -> %s\n", *slug, filepath.Base(dest))

	m := archive.NewManifest(*slug, stamp, fp, home, r.OSSFuzz(), r.WS, wss, man.BaseImage)

	// The corpus, counted independently BEFORE the tar and verified against
	// that count after. An archive short by a few files looks exactly like a
	// complete one, and a byte total cannot tell them apart.
	if !*noCorpus {
		for _, ws := range wss {
			src := campaign.WSDir(slugDir, ws)
			if !fileExists(filepath.Join(src, "corpus")) {
				src = r.Workspace(ws)
			}
			note := archive.TarCorpus(src, filepath.Join(dest, "corpus-"+ws+".tar.zst"))
			m.Corpus[ws] = note
			if !note.Verified {
				fmt.Fprintf(os.Stderr,
					"  !! corpus %s: archived %d of %d inputs%s\n",
					ws, note.Archived, note.Inputs, ifStr(note.Error != "", " ("+note.Error+")", ""))
			} else {
				fmt.Printf("  corpus %-14s %d inputs, verified\n", ws, note.Inputs)
			}
		}
	}

	// The record itself: the series is the campaign's own account of what ran.
	for _, name := range []string{"series.jsonl", "MANIFEST.json"} {
		if b, err := os.ReadFile(filepath.Join(slugDir, name)); err == nil {
			os.WriteFile(filepath.Join(dest, name), b, 0o644)
		}
	}

	if err := m.Write(dest); err != nil {
		fmt.Fprintf(os.Stderr, "pgfuzz: writing the manifest: %v\n", err)
		return 1
	}

	// THE SEAL, LAST. Applied after everything else so the whole directory --
	// manifest, corpus, series -- is inside it. Read-only is a statement the
	// index page already makes on this directory's behalf.
	if err := sealReadOnly(dest); err != nil {
		fmt.Fprintf(os.Stderr, "pgfuzz: sealing: %v\n", err)
		return 1
	}
	fmt.Printf("  sealed %s\n  fingerprint %s (fp_version %d)\n",
		dest, fp, archive.FPVersion)
	return 0
}

// sealReadOnly makes a run directory unwritable.
//
// Directories keep their execute bit or nothing can traverse them; files lose
// write for everyone. This does not stop root, and is not meant to -- it stops
// the tool, and the person, from amending a run that already happened.
func sealReadOnly(root string) error {
	return filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return os.Chmod(p, 0o555)
		}
		return os.Chmod(p, 0o444)
	})
}

func ifStr(cond bool, a, b string) string {
	if cond {
		return a
	}
	return b
}

# pg-fuzz

PostgreSQL fuzzing driven by one static Go binary, `pgfuzz`, on top of OSS-Fuzz
as a build substrate. No third-party Go dependencies, no shell scripts, no
Python. `project/build.sh` is the single exception: it is OSS-Fuzz's contract
and runs inside the build container.

Read this before changing anything. Most of what follows was paid for.

---

## The cornerstone: a campaign is self-contained and repeatable

**A campaign directory is the unit of work, and it must stand on its own.**
`campaigns/<slug>/` holds the builds that produced the findings, the logs those
builds wrote, the series the rounds appended, and a manifest naming exactly what
went in. You should be able to move that directory to another machine, point the
tool at it, and rerun coverage against the same binaries that did the fuzzing.

This is not tidiness. It is the difference between a finding you can defend and
a number you cannot explain six weeks later:

- A build that lives in a workspace is **overwritten by the next build of that
  workspace**. Once that happens the campaign's own results describe binaries
  that no longer exist, and a coverage rerun measures something else while
  reporting the campaign's name.
- Coverage measured against a *different* build than the one that fuzzed is the
  failure this project has already had: a coverage build spent two days
  measuring stock orafce while the fuzzing builds ran the patched one. Nothing
  said so, because both were "orafce".

Concretely:

- The campaign builds into `campaigns/<slug>/builds/<ws>/` and logs to
  `campaigns/<slug>/builds/<ws>.log`. It does not read a workspace's `builds/`.
- `campaigns/<slug>/MANIFEST.json` records, per workspace: the ref and the
  commit it resolved to, the sanitizer and engine, the config fingerprint, and
  the plugin provenance rows. A moving branch is useless as provenance; the
  resolved sha is the fact.
- Anything the campaign needs to be re-read later lives under the slug. If you
  add a phase that writes something a reader will want, write it there.

**What is deliberately NOT in the slug:** the corpus. Corpora belong to
workspaces, accumulate across campaigns, and reach millions of files; copying
one per campaign would cost more than it buys. `pgfuzz bundle` is the command
that produces a fully portable artifact including corpus, and it is what leaves
this machine. The slug is self-contained for *builds and results*; `bundle` is
self-contained for *everything*.

### Repeatability

- **The substrate is pinned.** `project/oss-fuzz.pin` names the oss-fuzz commit
  and the base image digest. `build` refuses to run against anything else
  rather than warning, because a build on the wrong substrate produces binaries
  that look identical and only diverge later as a fingerprint that moved --
  by which point the corpus has grown on the wrong substrate. `-no-pin` exists
  for deliberately testing a new one and says so on every line.
- **Plugin versions are per-workspace, and pinned by ref.** The registry
  (`project/plugins.tsv`) holds only what is a property of the plugin. Which
  version is the experiment variable.
- **A local plugin tree is recorded as `local:<sha>[+dirty]`, never `local`.**
  Two builds that both say "local" is not provenance.

---

## The four roots

Every path resolves through `internal/paths`. Never hard-code one.

| Root | Default | Holds |
|---|---|---|
| `PGFUZZ_HOME` | the checkout, found by walking up | tooling, harnesses, patches |
| `PGFUZZ_WS` | `~/pgfuzz` | workspaces, corpora, artifacts, campaigns |
| `PGFUZZ_CACHE` | `~/.cache/pgfuzz` | the postgres/orioledb/oss-fuzz clones |
| `PGFUZZ_SRC` | `~/Projects/sources` | patch files and locally patched plugin trees |

`PGFUZZ_HOME` is found by markers (`project/build.sh`, `go/go.mod`), not by
"three directories up" -- an installed binary once resolved it to `/`, and the
ratchet then read `/scripts/ratchet-baseline.json`, found nothing, printed an
empty baseline and exited 0. When no checkout looks right, `NeedHome()` refuses
and names where it looked.

**These roots may be on different filesystems.** That is the point of having
four. Anything that moves data between them must handle `EXDEV` -- `os.Rename`
across filesystems fails, and the first version of the build move reported
"keeping build in place" and carried on, leaving the workspace with no `builds/`
directory and 1.5G stranded in a tmpfs. Use `build.Move`.

---

## Ground rules

- **Nothing mutable in this repository.** Exports, builds, corpora and crashes
  live under `PGFUZZ_WS`. The repo holds the tool, `project/` and `tests/`.
- **Never build in a PostgreSQL checkout.** The build patches the tree and fills
  it with objects; each workspace gets its own `git archive` export.
- `project/` is symlinked into the oss-fuzz clone as `projects/pgfuzz-<ws>`, so
  the harnesses have one source of truth no matter how many workspaces exist.
- **The binary mounts itself into containers.** It is static and CGO-free, so it
  runs in any Linux image; hidden `_`-prefixed subcommands (`_fuzz`, `_repro`,
  `_covunion`, `_sql`, `_scenario`, `_own`, `_signal`) are the in-container
  halves. This replaced generated bash handed to `bash -c`. Do not reintroduce
  a generated shell string.
- **Containers run as root, so every writable bind mount leaks root-owned files
  to the host unless something hands them back.** 437,176 files and 36G had
  accumulated before anyone counted. Overlay the mount (`incontainer.MountOverlay`)
  or hand it back (`incontainer.Chown` via `PGFUZZ_UID`); `pgfuzz reown` is the
  repair for anything already on disk.

---

## The campaign control surface

A running campaign is a process, a marker file, and a set of containers. All
three have to be dealt with, and they are not the same thing.

| | What it is | Where |
|---|---|---|
| the driver | one `pgfuzz campaign` process | `campaigns/<slug>/live/campaign.json` records its PID |
| the marker | `campaign.json` + `entries`, written at start | `campaigns/<slug>/live/` |
| the work | one container per slice, named `pgfuzz-run-<ws>-<target>-<pid>` | `docker ps` |
| the record | append-only, survives a kill | `campaigns/<slug>/series.jsonl` |
| the provenance | what each build was | `campaigns/<slug>/MANIFEST.json` |
| the builds | the binaries that produced the findings | `campaigns/<slug>/builds/<ws>/` |

Commands:

- `pgfuzz campaign -slug NAME -hours H -w <ws>...` -- builds into the slug, then
  sweeps. `-rebuild` forces a rebuild, `-no-build` refuses to build and uses only
  what the campaign already has.
- `pgfuzz tui [<slug>|<path>]` -- the dashboard. **There is no "newest campaign"
  rule.** Name the slug, give a path, or stand inside one.
- `pgfuzz stop [-w <ws>]` -- kills the slice containers by name filter. This is
  the right way to stop work.
- `pgfuzz watchdog [-grace S] [-interval S] [-n]` -- kills containers that have
  outlived their slice. `-n` shows what it would do.
- `pgfuzz plateau -w <ws>...` -- says whether a workspace has stopped climbing.

**Alive means the PID is alive, not that the marker exists.** A marker outlives
`kill -9`, and a dashboard that trusts it reports a dead campaign as running
indefinitely.

### Killing things

Stop the containers, then the driver. Killing the driver alone leaves containers
running -- they are children of dockerd, not of the campaign.

```
pgfuzz stop                 # every slice container
pgfuzz stop -w gt-pg17      # one workspace's
docker ps                   # confirm; this is the instrument, not an assumption
```

**`pkill -f` is a trap, twice over.** The first is the classic one: your own
`pkill` command line contains the pattern, so it matches itself. Write the
pattern so it cannot: `pkill -f "pgfuz[z] campaign"`.

The second is the one that actually bites here and the bracket trick does NOT
fix: *any other process whose command line merely mentions the string* dies too.
A monitor shell running `until ! pgrep -f "pgfuzz build"; do ...; done` contains
`pgfuzz build` as text, so a `pkill -f "pgfuz[z] build"` kills the watcher along
with the build. That happened, and it silently took out five unrelated watchers,
including two left over from a previous campaign. Prefer `pgfuzz stop`; when you
must use a signal, target the recorded PID from `live/campaign.json` rather than
a pattern.

A slice killed mid-run is normal and is not a data loss: the durable log is
written inside the container onto a bind mount, and each slice is appended to
the series as it finishes rather than batched at the end of a sweep.

---

## Rules that produced the current design

### Absence of a signal is not absence of a problem

Check the instrument before trusting the reading. A tool that silently skips
what it cannot open reports a corpus of 20,000 as 400 and nothing looks wrong.
`corpus.Measure` counts what it cannot read *and* what it does not own,
separately -- ownership was added after 6,949 root-owned files hid from a repair
keyed only on readability, because a root-owned file at mode 0644 reads fine.

### Exit 0 is not proof of effect

The worst failure in this codebase is the one that succeeds. `ws -new -plugins`
recorded twelve plugins, `build` never read the list, and the build finished
with 23 targets and exit 0 -- a build with no plugins and a build whose plugins
were dropped were indistinguishable. When you add a step that can be skipped,
make the skip visible or make it impossible.

Likewise `helper.py` has returned 0 with no output directory: check what the
next stage receives, not the exit code.

### Three verdicts, never two

Reproduced, clean, and **could not run** are different, and they get different
exit codes. Reading "the image was missing" as "the bug is fixed" is how an
unreproducible finding reaches a maintainer. `repro` mounts the build under an
overlay for this reason: mounting it read-only makes `run_fuzzer`'s unconditional
`mkdir $OUT/<target>_<engine>_<san>_out` fail, which takes the whole reproduction
with it -- exit 1, no verdict, indistinguishable from "clean" to anything not
looking.

### Measure execution, not artifacts

An empty artifacts directory means "nothing crashed", not "nothing ran".
`#N INITED` versus `#M DONE` is what distinguishes a replay-only slice from a
real one, and libFuzzer's `exec/s` is cumulative, not instantaneous.

### The series is the model

`series.jsonl` is append-only and must survive a mid-round kill. Campaigns here
get killed mid-slice routinely; a slice that finished and was not recorded is a
slice that did not happen. Record each slice as it completes, not batched at the
end of a sweep.

### The durable log is the one on the bind mount

stdout is the fragile copy: a killed process loses what is buffered and one
broken pipe loses everything. libFuzzer deletes its own `fuzz-<i>.log` once it
has printed them, so a file written inside the container onto a bind mount is
the only record that outlives a kill.

### Say the number out loud

A moving branch (`origin/master`) means nothing in a report without the commit
it resolved to. Print it, record it, put it in the manifest.

---

## Gotchas already paid for

- `build.sh` runs under `set -eu`. Unset variables OSS-Fuzz does not export must
  be defaulted, and `patch -N` exits non-zero on an already-applied patch, so
  patches go through `apply_patch`, which tolerates that and then asserts the
  marker landed.
- OSS-Fuzz's `compile` runs the coverage source copy **after** `build.sh`
  returns, so `build.sh`'s own chown trap cannot cover it. `BUILD_UID` is
  upstream's answer and is unavailable here: it runs `build.sh` unprivileged,
  and ours needs root for `useradd`, `chown` and `apt-get`.
- `-max_len` is stated rather than left to libFuzzer, which silently adopts the
  largest corpus entry once a corpus exists -- so the effective limit drifts and
  two runs of "the same" target stop being comparable.
- The overlay's `work/` directory is mode 000 and root-owned. Host-side cleanup
  of an overlay upper layer can only ever succeed on a directory the container
  already emptied; do the removal inside, as root.
- Harnesses that take a variant selector consume the **first input byte**. A
  seed corpus without the right selector byte seeds the wrong variant.
- Standalone harnesses have **no catalog**. Anything reaching
  `SearchCatCacheInternal` belongs in a backend-initialized harness and is not a
  PostgreSQL bug. `oidvectorrecv` and `int2vectorrecv` delegate to `array_recv`
  and are not obvious.
- `initdb` refuses to run as root and everything in a container is root; the
  server paths run as uid 1000. Use the **project's builder image**, not
  `base-runner`, which lacks the `libicu` the server binaries link.
- `su` is setuid, so glibc drops `LD_LIBRARY_PATH` across the exec. Set it
  *inside* the shell `su` starts.
- Plugins are pinned for PostgreSQL 17. They degrade on newer majors: on PG18
  `pgaudit` 17.1 fails (`standard_ExecutorRun` lost an argument) and on
  PG19devel only five of twelve build. A plugin set is per-major, and the
  manifest is what records which one a build actually got.

---

## Triage discipline

Findings get a **recorded verdict**, never a quiet deletion. The reasoning and
the reproduce command go in the work log before anything is archived, so a
verdict that later turns out to be wrong can be re-opened.

Prefer fixing the harness over arguing about the finding. A harness that feeds
input PostgreSQL could never receive produces crashes that can never happen, and
then every one needs a human to wave it through -- which is the state in which a
real bug gets waved through too.

**Plausible is not verified.** The `encoding_fuzzer` overflow was correctly
called a harness artifact for a mechanism that was wrong on the first telling.
Check the mechanism; do not reason from what sounds right.

---

## Work log

Every build, run, harness change and crash triage goes in `WORKLOG.md`.
Failures and dead ends too -- a dead end nobody recorded gets walked twice.

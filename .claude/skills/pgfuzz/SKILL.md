---
name: pgfuzz
description: Drive the pgfuzz PostgreSQL fuzzer - set up a fresh machine, create workspaces, build, run campaigns, watch the dashboard, reproduce and triage findings, and produce a sealed reportable campaign. Use whenever the task involves pgfuzz, a fuzzing campaign, a workspace, a slug, a corpus, the ratchet, or a crash artifact from this project.
---

# pgfuzz

One static Go binary on top of OSS-Fuzz. No shell scripts, no Python, no
third-party Go dependencies. `project/build.sh` is the one exception: it is
OSS-Fuzz's contract and runs inside the build container.

Read `AGENTS.md` in the repository root before changing the tool. This skill is
about *driving* it.

`pgfuzz` with no arguments prints the whole command surface. Prefer that over
guessing a flag.

---

## The three ideas everything else follows from

**1. A workspace is an experiment.** It pins one PostgreSQL ref, one sanitizer,
one plugin set, one patch set. Two workspaces exist so two things can be
compared; `workspace.conf` *is* the experiment and overwriting one makes every
result already recorded against it unattributable.

**2. A campaign owns its results.** `campaigns/<slug>/` holds the builds that
produced the findings, the corpora they fuzzed when sealed, the series, and a
manifest naming what went into each build. It is meant to stand on its own.

**3. Sealed or not is the difference between a run you can report and a run you
can only have done.** Default shares the workspace corpus, which is right
locally — the corpus is the accumulated value of every campaign before it.
`-sealed` gives the campaign its own corpus that nothing outside can change.

---

## Roots

Every path resolves through these. Never hard-code one; override by environment.

| Root | Default | Holds |
|---|---|---|
| `PGFUZZ_HOME` | the checkout, found by walking up | tooling, harnesses, patches |
| `PGFUZZ_WS` | `~/pgfuzz` | workspaces, corpora, artifacts, campaigns |
| `PGFUZZ_CACHE` | `~/.cache/pgfuzz` | postgres / orioledb / oss-fuzz clones |
| `PGFUZZ_SRC` | `~/Projects/sources` | vendor patches, locally patched plugin trees |

They may be on different filesystems — that is the point of having four.

---

## From nothing to a campaign

```bash
pgfuzz bootstrap                     # clone postgres, orioledb, oss-fuzz; check
                                     # oss-fuzz out at project/oss-fuzz.pin
pgfuzz pin -check                    # substrate matches the pin?
pgfuzz ws -new pg17 -ref origin/REL_17_STABLE -sanitizer address \
          -plugins "pgaudit pg_cron orafce"
pgfuzz build -w pg17                 # ~1-5 min; longer with plugins
pgfuzz targets -w pg17
pgfuzz run -w pg17 -t xlogreader_fuzzer -time 60
pgfuzz campaign -slug nightly -sealed -hours 2 -jobs 8 -time 45 \
          -w pg17 -w pg18
pgfuzz tui nightly
```

`bootstrap -cache DIR` or `PGFUZZ_CACHE=DIR` puts the clones elsewhere — useful
for rehearsing a fresh machine.

### Workspace knobs beyond `ws -new`

Edit `workspace.conf` directly; these are read at build time.

- `plugins=` — `name`, `name@ref`, `name@url@ref`, `name@/local/path`.
  A local tree is recorded as `local:<sha>[+dirty]`, never a bare `local`.
- `extensions=` — contrib extensions to build and CREATE, e.g.
  `pg_stat_statements dblink`. `pg_profile` and `pg_stat_kcache` want
  `pg_stat_statements`; `pg_profile` also wants `dblink`.
- `preload=` — libraries to put in `shared_preload_libraries` **before** the
  plugins that declare `preload=yes`. Order matters: `pg_stat_kcache` must come
  after `pg_stat_statements` or the postmaster refuses to start.
- `gucs=` — e.g. `cron.database_name='dbfuzz'`, which `pg_cron` needs or
  `CREATE EXTENSION` fails.
- `patch=` — whitespace-separated absolute paths, applied **in order** on the
  host against the export, before the container runs. The series is judged as a
  whole: a later patch may repair an earlier one, so per-patch exit status means
  nothing — a leftover `.rej` fails the build. Hunks apply with fuzz (`-F3`), so
  a patch written for a neighbouring minor release will usually still land.
  `patch_applied` is recorded in `workspace.conf` afterwards.

Verify registry pins with `pgfuzz plugins -f project/plugins.tsv`.

---

## Watching a campaign

```
pgfuzz tui <slug>|<path>     # or stand inside the campaign directory
```

There is **no "newest campaign" rule.** Name the slug, give a path, or run from
inside one.

Reading the grid:

```
·· not built    × build failed    (blank) idle    ◐ building
●  fuzzing      ·  swept clean    N reproducers found
```

Columns to the right: round, targets swept this round, reproducers, corpus size,
inputs added, coverage, executions, and the **resolved commit** — a moving branch
is not provenance.

---

## Stopping

Stop the containers, then the driver. Killing the driver alone leaves containers
running; they are children of dockerd, not of the campaign.

```bash
pgfuzz stop                 # every slice container
pgfuzz stop -w pg17         # one workspace's
docker ps                   # confirm - the instrument, not an assumption
```

The driver's PID is in `campaigns/<slug>/live/campaign.json`. Signal that.

**Never `pkill -f`.** The bracket trick (`pkill -f "pgfuz[z] build"`) only stops
the `pkill` matching *itself*; any other process whose command line merely
*mentions* the string dies too — a watcher looping on `pgrep -f "pgfuzz build"`
is killed along with the build. That has happened here and took five unrelated
watchers with it.

A slice killed mid-run is not data loss: the durable log is written inside the
container onto a bind mount, and each slice is appended to the series as it
finishes.

---

## Findings

```bash
pgfuzz repro -w pg17 -t xlogreader_fuzzer <artifact>
pgfuzz triage -w pg17 -t xlogreader_fuzzer -verdict "harness artifact: ..." <artifact>
pgfuzz sql -w pg17 file.sql            # things a fuzz target cannot carry
pgfuzz scenario -w pg17 seedN.json     # replay a recorded storage scenario
```

**Three verdicts, not two.** `repro` exits 0 reproduced, 1 clean, 2 could not
run. Reading "the image was missing" as "the bug is fixed" is how an
unreproducible finding reaches a maintainer.

Findings get a **recorded verdict**, never a quiet deletion, so a verdict that
later proves wrong can be re-opened.

For a storage finding, **the seed is not the reproducer — `seedN.json` is.**
Changing the generator changes what a seed produces.

---

## Making a campaign reportable

```bash
pgfuzz campaign -slug release-check -sealed ...   # own corpus, movable
pgfuzz clone release-check /media/stick/rc        # standalone copy
pgfuzz bundle -slug release-check -cov pg17-cov   # portable artifact + coverage
pgfuzz report -slug release-check -html report.html
pgfuzz index -slug release-check
```

`clone` refuses an unsealed campaign: what it would capture is whatever the
workspace corpus holds *now*, not what the campaign fuzzed, and the result would
look reportable without being so.

---

## Corpus and the ratchet

```bash
pgfuzz corpus -w pg17 -repair                  # fix ownership/readability
pgfuzz corpus -w pg17 -minimize -cap 20000
pgfuzz corpus -w pg17 -seed-from-source /path/to/postgres
pgfuzz gate -w pg17                            # did this run clear the floor?
pgfuzz ratchet -w pg17 -show
pgfuzz ratchet -w pg17 -update
pgfuzz ratchet -w pg17 -profile experiment      # isolated baseline
pgfuzz plateau -w pg17                         # still climbing?
```

Use `-profile` for anything that must not touch the committed baseline.

---

## Housekeeping

```bash
pgfuzz reown -all              # take back root-owned files
pgfuzz reown -all -n           # what would change
pgfuzz tidy -apply -docker     # reclaim space
pgfuzz ws                      # every workspace (bare: there is no -list)
pgfuzz inventory               # what exists
pgfuzz watchdog -n             # containers outliving their slice
```

Containers run as root, so any writable bind mount can leave root-owned files.
`reown` is the repair.

---

## Things that will bite

- **Exit 0 is not proof of effect.** A build succeeds with plugins missing;
  `helper.py` has returned 0 with no output directory. Check what the next stage
  actually received. `MANIFEST.json` records which plugins a build really got.
- **Plugins are pinned for PostgreSQL 17 and degrade on newer majors.** On PG18
  `pgaudit` 17.1 fails to compile; on PG19devel five of twelve do. Use per-major
  refs (`pgaudit@REL_18_STABLE`, `pgaudit@main`) or drop what will not build —
  and let the manifest record it.
- **A branch does not resolve by its bare name** in a plugin clone; only tags do.
  The tool retries as `origin/<ref>`.
- **The substrate is pinned and `build` refuses to run against another one.**
  `-no-pin` exists for testing a new substrate and says so on every line.
- **An empty artifacts directory means "nothing crashed", not "nothing ran".**
  Measure execution.
- **Absence of a signal is not absence of a problem.** Check the instrument
  before trusting the reading.

---

## Work log

Every build, run, harness change and crash triage goes in `WORKLOG.md`, failures
and dead ends included — a dead end nobody recorded gets walked twice.

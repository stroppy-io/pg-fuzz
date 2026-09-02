# pg-fuzz

Fuzzing PostgreSQL, and the extensions people actually run it with, on top of
OSS-Fuzz. Twenty-three harnesses, a build that carries your patches and
out-of-tree extensions with it, and one static binary that drives the whole
thing.

The point of the design is a finding somebody else can confirm. A campaign
directory holds the binaries that produced its results, the corpus they fuzzed,
and a manifest saying exactly what went into each build — so it can be handed to
a maintainer, or to a vendor, and re-measured there.

```bash
pgfuzz bootstrap
pgfuzz ws -new pg17 -ref origin/REL_17_STABLE -sanitizer address
pgfuzz build -w pg17
pgfuzz campaign -slug nightly -sealed -hours 2 -jobs 8 -w pg17 -w pg18
pgfuzz tui nightly
```

## What it fuzzes

Twenty-three targets, each entered where PostgreSQL itself takes untrusted
input:

`backend_types` `binary_recv` `config_file` `conninfo` `datetime` `encoding`
`extension_funcs` `formatting` `geo` `hba_file` `json_parser` `jsonb`
`jsonpath` `network` `numeric` `protocol` `raw_parser` `regex` `scalar_types`
`simple_query` `spi_query` `tsearch` `xlogreader`

Some run against a bare library; others need a backend initialised far enough to
have a catalog. `extension_funcs` walks the SQL surface of whatever extensions a
workspace asked for, which is how out-of-tree code gets covered at all.

Beyond the fuzz targets: `pgfuzz sql` runs a statement against a real postmaster
started from the workspace's own build, and `pgfuzz scenario` replays a recorded
storage scenario — for findings a fuzz target cannot carry, the ones that are
"run this against a server and watch".

## Requirements

`docker`, `git`, `python3` (OSS-Fuzz's `infra/helper.py`), and Go 1.27 to build
the binary. Nothing else: the Go module has **no third-party dependencies**, on
purpose — a binary handed to a vendor so they can confirm a defect should not
need a module proxy to build.

`pgfuzz bootstrap` clones PostgreSQL, OrioleDB and OSS-Fuzz, and checks OSS-Fuzz
out at the commit `project/oss-fuzz.pin` names.

## The shape of it

| | |
|---|---|
| **workspace** | one experiment: a ref, a sanitizer, a plugin set, a patch set. `workspace.conf` *is* the experiment. |
| **build** | `infra/helper.py build_fuzzers` against `project/`, which carries the harnesses, the patches and the recipe. |
| **slice** | one target for N seconds. Appended to the series as it finishes, so a kill mid-round loses nothing already done. |
| **sweep** | every target in a workspace, most-productive-first. |
| **round** | a sweep of every workspace, rotated so the same arm is not always the one the deadline cuts. |
| **campaign** | rounds until a deadline, published under `campaigns/<slug>/`. |

Where things live — four roots, each overridable, so the clones can sit on a
fast disk and the corpora on a big one:

| Root | Default | Holds |
|---|---|---|
| `PGFUZZ_HOME` | the checkout | tooling, harnesses, patches |
| `PGFUZZ_WS` | `~/pgfuzz` | workspaces, corpora, artifacts, campaigns |
| `PGFUZZ_CACHE` | `~/.cache/pgfuzz` | the postgres / orioledb / oss-fuzz clones |
| `PGFUZZ_SRC` | `~/Projects/sources` | your patch files and locally patched plugin trees |

## Sealed campaigns

A campaign run normally **shares** its workspaces' corpora, which is what you
want locally: the corpus is the accumulated value of every campaign before it,
and a run that contributes back is worth more than one that starts cold.

`-sealed` gives the campaign its own corpus, hard-linked at the moment it
started. Nothing outside can change it — no minimize, no other campaign — and it
travels with the directory:

```
campaigns/<slug>/
  MANIFEST.json          ref, resolved sha, sanitizer, plugins, per build
  series.jsonl           append-only, one row per slice
  live/campaign.json     the driver's PID
  ws/<name>/build/       the binaries that did the fuzzing
  ws/<name>/corpus/      what they fuzzed
  ws/<name>/artifacts/   what they found
```

`pgfuzz clone <slug> <dest>` makes a standalone copy — and refuses an unsealed
campaign, because what it would capture is whatever the workspace corpus holds
*now*, not what the campaign fuzzed.

## Not losing findings

- **Three verdicts, not two.** `repro` exits 0 reproduced, 1 clean, 2 could not
  run. Reading "the image was missing" as "the bug is fixed" is how an
  unreproducible finding reaches a maintainer.
- **Findings get a recorded verdict**, never a quiet deletion, so one that later
  proves wrong can be re-opened.
- **The ratchet** keeps a floor per workspace and target, with CUSUM as a
  second, more sensitive layer: a run that quietly stops finding things is a
  regression in the harness as often as it is good news.
- **A moving branch is not provenance.** `origin/master` is recorded as the
  commit it resolved to.

## Custom patches

A workspace can carry a patch series of your own — a distribution's changes, a
proposed fix, a backport, anything `patch(1)` can apply:

```
patch=/path/to/0001-my-change.patch /path/to/0002-fixup.patch
```

Whitespace-separated and **applied in order**, on the host, against the export,
before the container ever runs. The export is remade on every build, so patches
belong here rather than applied by hand to a checkout — a hand-patched tree is
gone the next time anything is rebuilt.

Two details that matter:

- **The series is judged as a whole, not patch by patch.** A later patch
  commonly repairs what an earlier one could not apply, so a non-zero status
  partway through says nothing about the final tree. Leftover `.rej` files do,
  and any of them **fails the build** — a half-patched tree compiles fine and
  then fuzzes something that is not what anyone thinks it is.
- **Hunks are applied with fuzz** (`-F3`), because a patch written against one
  minor release usually has to sit on another. That is deliberate and it is
  permissive: a hunk whose context has drifted will still land. What cannot be
  fuzzed away is a hunk with nowhere to go, which is what the `.rej` gate
  catches.

`workspace.conf` records `patch_applied` after a successful build, and the
campaign manifest carries it, so a finding can always be traced to the tree it
was found in.

Combine with `plugins=` to fuzz a patched PostgreSQL *and* the extensions that
run on top of it — which is the case the `extension_funcs` target exists for.

## Extensions

`project/plugins.tsv` is a registry of where to fetch an extension, what it
needs to build, whether it must be preloaded, and what `CREATE EXTENSION` wants.
Which extensions, and at which version, is a per-workspace decision — that is
the experiment variable, and comparing a plugin before and after a fix is
exactly what workspaces are for.

Plugins are pinned for PostgreSQL 17 and degrade on newer majors: on 18 pgaudit
17.1 no longer compiles, and on 19devel five of twelve fail on real API changes.
A workspace can name a per-major ref, and `MANIFEST.json` records what each
build actually contained.

## Layout

```
go/          the tool: cmd/pgfuzz plus ~30 internal packages
project/     what OSS-Fuzz builds -- harnesses, build.sh, patches, plugins.tsv
tests/       the red/green suite: cases, inputs, preconditions, fixes
scripts/     data, not code: ratchet baselines and accept-lists
```

`project/build.sh` is the one piece of shell, because it is OSS-Fuzz's contract
and runs inside the build container.

## Further

- `AGENTS.md` — the invariants, and why each one exists. Read it before changing
  the tool.
- `.claude/skills/pgfuzz/` — a task-oriented guide to driving it.
- `pgfuzz` with no arguments — the full command surface.

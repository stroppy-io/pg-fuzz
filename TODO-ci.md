# CI — what exists, what is unproven, what is left

Status as of 2026-09-04. Written because the point of this CI is to catch a
botched script before somebody spends twenty hours on it, and a CI that has
never been run is itself an unproven script.

## Done, and verified by running it

- **`scripts/ci.sh`** — the whole code CI, runnable locally: no-third-party-deps,
  build, `vet`, `gofmt`, `go test`, `go test -race`, the wiring checks, the
  harness syntax pass. Green here.
- **`.github/workflows/ci.yml`** — three jobs, one line each, calling that
  script. So "green locally" and "green on GitHub" are one claim, not two that
  drift.
- **`act` via mise** (0.2.89), `~/.config/act/actrc` pinned to the medium
  image. All three jobs pass in real containers.
- **Three latent failures in the committed workflow**, none of which anyone
  could have seen without running it:
  - Go 1.24 pinned while `go/go.mod` declares 1.27 — a toolchain that cannot
    build the module. Now read from `go.mod` with `go-version-file`.
  - `cache-dependency-path: go/go.sum` pointing at a file that does not exist,
    because there are no dependencies. `setup-go` fails before running anything.
  - The harness check inverted: `grep -qvE "file not found"` succeeds whenever
    *any* line does not match, and clang always prints a source line, a caret
    and "1 error generated."
- **Two tests that asserted things meaningless to root**, which is what CI
  containers run as: an archive seal probe and a corpus permission check. They
  skip explicitly now rather than fail.
- **`pgfuzz bootstrap -shallow -only`** — a disposable runner does not need
  1 GB of PostgreSQL history or the OrioleDB clones.
- **`pgfuzz campaign -no-pin`** — a smoke run is not a campaign, and five
  moving branches drift constantly.
- **`project/patches/0001-ci-marker.patch`** — a real patch that adds a file
  nothing compiles, so it applies to every major from 16 to master and cannot
  change what is built. It proves the patch pipeline ran, which was dead once.

## Written but NOT yet proven

- [x] **`scripts/smoke.sh` GREEN**, on the fifth run: campaign, gates, report,
      index, bundle, census, inventory, breakdown, all ok, in about 25 minutes
      against vfy-pg17 at 8s a target. Five runs, each finding something
      real, and every failure was the tool being correct:
      - a wrong flag of mine (`-o` for `-out`);
      - the PG pin refusing a moved branch — right for a campaign, noise for a
        smoke run, hence `campaign -no-pin`;
      - `breakdown` exiting 2 on a workspace with no crashes — correct by this
        project's rule that absence is never a pass, so the script accepts it;
      - starvation at 8,544 executions against a floor of 10,000 — an
        eight-second slice genuinely starves, so the smoke uses a floor of 100:
        low enough for anything that ran, high enough to still fail a target
        that executed nothing;
      - `simple_query_fuzzer` spending its whole slice on corpus replay, which
        killed a flag I had just added (see below);
      - `round-complete` firing because a 7-minute campaign cannot finish a
        23-target round, so the clock went to 0.35h for two complete rounds.
      That is six corrections to one script’s expectations, and every failure
      was the tool being right.

      **A flag removed, not kept.** I added `-no-budgets` to skip the 150s and
      200s floors on the two slow targets. Skipping them *creates* the
      condition the replay gate exists to catch — the budget and the gate
      encode one fact from opposite sides. An escape hatch that manufactures
      the failure it avoids is the dead surface this audit spent two days
      deleting, so it is gone and the budgets stay on.
- [x] **`.github/workflows/sweep.yml` — GREEN, 10 of 10**, run 33899248721 on
      2026-09-04. pg16 through 19 and master, address and undefined, each with
      the CI marker patch and plugins, every item producing a 4+ MB record.

      **"`act` cannot run this" was wrong, and it was mine.** The line that
      stood here — "the oss-fuzz build needs docker inside the runner
      container" — was written without trying it. act mounts the host docker
      socket, so the build runs on the HOST daemon and works. Two adjustments
      were needed, both the same shape: anything the build container mounts has
      to exist for the daemon that starts it, and act's `$RUNNER_TEMP` and
      `$HOME` do not. `PGFUZZ_ACT_ROOT` points the roots and the binary at one
      shared path; it is unset on a real runner. The whole pipeline now runs
      here, including both artifact uploads, via `act --artifact-server-path`
      rather than an exemption.

      Eleven defects were found by running it, every one mine, none visible
      without a run. The scaffolding ones:

      1. `reclaim disk` deleted `$AGENT_TOOLSDIRECTORY`, where setup-go had
         just installed Go — exit 127.
      2. `$HOME/.local/bin` did not exist and was not on `PATH`.
      3. `bootstrap -shallow` could not reach the pinned oss-fuzz commit.
      4. A duplicate build without `-no-pin`.
      5. **An uppercase docker tag.** A workspace name becomes a docker
         repository name, and `ci-REL_17_STABLE-address` is not lowercase.
         This alone killed all ten items.
      6. **The wipe could not wipe.** Container-written files are root-owned,
         `rm -rf` left a workspace behind, and nothing checked. A surviving
         build satisfying a later check is a false green — the one thing this
         job exists to prevent.
      7. **Every upload glob named the unsealed layout** while a sealed
         campaign writes under `campaigns/ci/ws/<ws>/`, so a sweep that
         CRASHED would have uploaded no reproducer and stayed green.
      8. **`run-*.log` missed `run-*.log.gz`** — five of 23 targets silently
         absent from the record, upload green regardless.

      And four that were tool defects, not CI ones:

      9. **census could not see a sealed campaign.** 15 signatures from 46 logs
         were invisible on this host's real grande-teste campaign, and every
         sealed bundle wrote "census: no logs to scan" into its manifest.
      10. **The accept-list scope matched nothing.** `tm2timestamp` is scoped
          `pg16*,pg17*,oriole*` and CI workspaces are `ci-rel_16_stable-*`, so
          an ACCEPTED site read as out of scope and every undefined item failed
          on the row meant to excuse it. `matchGlob` also only handled a
          trailing star, so no scope could name a sanitizer.
      11. **`hasStackFix` fed "19beta3" to Atoi**, answered "no fix" for a tree
          that has it, and refused every REL_19 address build under a message
          that blamed upstream's commit for our parse.

      Plus two upstream facts, neither a defect here: pg_background v1.5 does
      not build on 18+ (v2.0.3 does, 14 through 19) and pg_background 2.0
      refuses PG 20 outright, so master sweeps without it; and pgaudit is
      versioned BY PostgreSQL major, so the sweep names 16.1/17.1/18.0/
      19beta3/main per ref.

- [x] **The sweep goes red for the HARNESS, not for findings.** A UB site is
      the fuzzer working, and failing the round on it makes a board nobody
      reads — at which point the starvation gate, whose whole job is to notice
      the harness silently doing no work, arrives unseen. `gate.Verdict` now
      says what a failure is About: starvation, slow-units, final-stats and
      round-complete are Harness; ubsan and ubsan-withdrawal are Finding.
      `pgfuzz gate` exits 1 for the first and 3 for the second, `smoke.sh`
      accepts 3. Nothing is muted: both are printed, both recorded, and the
      report ships them. Verified in the green run — the record reads
      `"gate":"finding","detail":"the fuzzer found something; the harness
      passed every gate"`.

- [x] **The harness is asserted to still SEE**, which nothing here did before.
      `pgfuzz expect` against `project/ci-findings.tsv`: 7 sites, each observed
      in BOTH 16 and 17 at 30s a target with near-identical counts, asserted
      as `found` (innermost frame of a UB report) AND `reported` (the census
      made a signature naming the file). It is the one check that fails on
      silence. Proven both ways: 7/7 on the real artifacts, 7/7 MISSED when
      the same logs are replayed with the UB reports stripped.

- [ ] **The disk arithmetic is from this host, not a runner.** ~8.5 GB per item
      against ~14 GB is measured locally (base-builder 3.15 GB, project layers
      ~0.3, shallow clone ~250 MB, export ~2.6 GB, address build 1.5 GB). It
      has not been observed on a GitHub runner.
- [x] **Artifact upload paths were guesses, and every one was wrong.** They
      named `$PGFUZZ_WS/<ws>/artifacts/…`, the UNSEALED layout, while
      `smoke.sh` runs `campaign -sealed -slug ci` and writes under
      `campaigns/ci/ws/<ws>/`. Nothing matched — and with
      `if-no-files-found: ignore`, a sweep that CRASHED would have uploaded no
      reproducer and still gone green.

      Checked against a real sealed campaign on this host rather than guessed
      again, and split in two: reproducers may legitimately be empty
      (`ignore`), the record may not (`error`). Note what `error` actually
      buys — upload-artifact fails only when NO path matches, so it catches
      "produced nothing at all", not "the manifest is missing". Per-file
      assertions stay in `smoke.sh`.

## Found by the sweep, not a CI problem

- [ ] **An empty `crash-` artifact is a leak report with no reproducer.** The
      first green sweep saved a zero-byte
      `crash-da39a3ee5e6b4b0d3255bfef95601890afd80709` for two targets —
      `da39a3ee…` being the sha1 of the empty input, verified. Nothing crashed:
      LeakSanitizer's check runs at process exit, libFuzzer had no input to
      attribute the leak to, and so it wrote the empty unit and named it
      `crash-`.

      **`-detect_leaks=0` is what makes it empty and misnamed.** The chain,
      from `/src/libfuzzer/FuzzerLoop.cpp` in the pinned base-builder:

      - `ExecuteCallback` sets `CurrentUnitSize = Size` (611) before the target
        runs and resets it to 0 (627) the moment the callback returns, while
        `CurrentUnitData` stays allocated for the life of the process.
      - LSan's shutdown check finds the leaks and calls `Die()`, which invokes
        the death callback libFuzzer registered at 142.
      - `DeathCallback` (190) is generic: `DumpCurrentUnit("crash-")`, prefix
        hardcoded.
      - `DumpCurrentUnit` (174) returns early only when `CurrentUnitData` is
        null. It is not. So it prints the mutation sequence and
        `; base unit: …` from stale state — which is why the log shows an
        `MS: 10 CrossOver-…` line for an input that had nothing to do with it —
        and writes `CurrentUnitSize` bytes. Zero of them.

      libFuzzer's OWN leak path (712) sets `CurrentUnitSize = Size` before
      `DumpCurrentUnit("leak-")`, so it writes a real, correctly named
      reproducer. That is precisely the path `-detect_leaks=0` disables, and
      libFuzzer says as much in its own message: "If LeakSanitizer is enabled
      in this process it will still run on the process shutdown."

      So the flag does not suppress the leak report. It downgrades it from a
      `leak-<sha1>` with a reproducer to an anonymous empty `crash-`.

      **The leaks themselves are two different things, and only one is real.**
      Two targets of 23 report anything, and the 95 reports split as:

      - `__interceptor_strdup`/`malloc` → `curl_slist_append` → `http_request`,
        60 of them, all in `extension_funcs_fuzzer`. That is **pgsql-http**, a
        curl slist that is not freed, and it looks like a genuine plugin leak.
        Worth reporting upstream once confirmed outside the fuzzer.
      - `AllocSetContextCreateInternal` under `ExecHashTableCreate`,
        `tuplesort_begin_common`, `spi_dest_startup`,
        `CreateExprContextInternal`, `CreateExecutorState`, `hash_create`,
        `SPI_connect_ext` — the rest. These are PostgreSQL memory contexts,
        released by context reset at transaction end rather than by `free()`,
        so LSan calls them leaks whenever a fuzzer exits mid-transaction. Not
        defects.

      Two problems wearing one filename: a plausible pgsql-http leak, and an
      artifact that misdescribes itself. The naming is the CI-relevant half —
      an empty `crash-` file is indistinguishable from a real reproducer to the
      artifact count, the upload, and whoever triages it, and the report
      already has to explain that an artifact is not a finding.

      Two coherent choices, and the current setting is neither:

      1. `ASAN_OPTIONS=detect_leaks=0` for these slices. No leak check, no
         artifact, and the pgsql-http leak is not this campaign's job.
      2. Drop `-detect_leaks=0` and let libFuzzer check. The leak is then
         caught during fuzzing, named `leak-`, and comes WITH the input that
         provoked it. Costs time on every mutation, and PostgreSQL's memory
         contexts will trip it constantly — libFuzzer has a guard for exactly
         that case (700: "the target function accumulates allocated memory in
         a global state w/o actually leaking it"), which is a fair description
         of a memory context.

      Whichever, a zero-byte file should not be called `crash-`.

## Left to build

- [x] **`sweep.yml` calls `scripts/smoke.sh`**, as `ci.yml` calls `ci.sh`.
- [x] **A coverage SHAPE check** — `scripts/smoke-coverage.sh`, GREEN, and it
      found something on its first run: the union printed its percentages and
      never named the anchor. The summary had recorded it and the HTML report
      had printed it since the audit; the command itself did not, which is
      where most people read that number. Fixed.

      It It asserts that a measurement produces all four counters with
      non-zero denominators, that the union can see the profiles the
      measurement just wrote, and that it names the anchor its percentages are
      against. All three defects it checks for were live this week and all
      three were invisible to a percentage.
- [ ] **Decide whether `pgfuzz regress` belongs in CI.** It builds a whole
      second PostgreSQL and runs `make check` — verified working here, 225
      tests passing, but ~40 minutes. Probably one item, not ten.
- [ ] **Cadence — YOUR CALL, and deliberately not taken.** The sweep is
      `workflow_dispatch` only. It is now green, which was the condition for
      giving it a push trigger, but ten items at ~25 minutes on every push to
      main is a real bill and the campaign config is moving to its own repo
      anyway. Options: leave it manual, add push-to-main, or nightly.

- [x] **GitHub no longer truncates the smoke step log.** oss-fuzz runs build.sh
      under shell tracing and PostgreSQL's make echoes every compiler
      invocation, so one item emitted 3.5 MB and the step was cut off long
      before the failure — every diagnosis in this file had to come from the
      uploaded artifacts instead.

      `build.Filter` thins the LIVE copy only: shell xtrace and compiler
      command lines go, build.sh's own messages, configure's checks, warnings
      and errors stay. Measured on a real build log from the green run:
      3,472 KB to 413 KB, 88% of it noise. Safe by construction — Fuzzers()
      tees into a buffer written to build.log whole, pass or fail, and the
      failure path already prints interesting() plus that path, so nothing
      dropped here is lost. An error line is never dropped whatever it looks
      like, which is the one rule that makes the rest of it defensible.

## Deliberately not in CI

- **Corpus caching.** Corpus size is a function of time, and a cache shared by
  ten items against a 10 GB repository quota buys thrash rather than reach.
  Every item starts cold on purpose.
- **Coverage magnitude.** A coverage build is 4.6 GB against an address build's
  1.5, and the number it produces after eight seconds a target says nothing
  anyone should read. The shape is worth checking; the percentage is not.
- **Finding bugs.** A green sweep means the tool is sound, not that the fuzzer
  found nothing. Reading it the other way is the artifact-versus-finding
  confusion the reports spend a section correcting.

## Elsewhere, not CI

- [x] README contributing section.
- [ ] **Push the CI commits.** The 101 fix commits are already on the remote
      (pushed 2026-09-04 10:24), so this is a fast-forward and no force is
      needed. It is blocked on one thing: the `gh` OAuth token has no
      `workflow` scope, so it may not write `.github/workflows/`. One
      interactive command unblocks it:

          gh auth refresh -h github.com -s workflow

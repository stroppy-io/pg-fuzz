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
- [ ] **`.github/workflows/sweep.yml` — executing, not yet green.** It has now
      run on GitHub (all ten items red) and locally under `act`.

      **"`act` cannot run this" was wrong, and it was mine.** The line that
      stood here — "the oss-fuzz build needs docker inside the runner
      container" — was written without trying it. act mounts the host docker
      socket, so the build runs on the HOST daemon and works. Two real
      adjustments were needed, both of the same shape: anything the build
      container mounts must exist for the daemon that starts it, and act's
      `$RUNNER_TEMP` and `$HOME` do not. `PGFUZZ_ACT_ROOT` points the roots and
      the binary at one shared path; it is unset on a real runner.

      Six defects have been found by running it, every one of them mine and
      none visible without a run:
      1. `reclaim disk` deleted `$AGENT_TOOLSDIRECTORY`, where setup-go had
         just installed Go — exit 127.
      2. `$HOME/.local/bin` did not exist and was not on `PATH`.
      3. `bootstrap -shallow` could not reach the pinned oss-fuzz commit.
      4. A duplicate build without `-no-pin`.
      5. **An uppercase docker tag.** A workspace name becomes a docker
         repository name, and `ci-REL_17_STABLE-address` is not lowercase.
         This alone killed all ten items on GitHub.
      6. **The workspace wipe could not wipe.** Container-written files are
         root-owned, so `rm -rf` left a workspace behind and nothing checked.
         A surviving build satisfying a later check is a false green, which is
         the one failure this job exists to prevent.
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

- [ ] **An empty `crash-` artifact is a leak report, not a crash.** The first
      green sweep saved `crash-da39a3ee5e6b4b0d3255bfef95601890afd80709` for
      two targets — `da39a3ee…` being the sha1 of the empty input. Nothing
      crashed: LeakSanitizer runs its check at process EXIT and writes a
      zero-byte "Test unit" for a leak that belongs to no input.

      `-detect_leaks=0` is already passed and does not prevent this: it is a
      libFuzzer flag governing libFuzzer's own leak checks during fuzzing,
      while LSan's at-exit check is an ASan runtime option (`ASAN_OPTIONS`).

      It matters because an empty `crash-` file is indistinguishable from a
      real reproducer to everything downstream — the artifact count, the
      upload, and whoever triages it. The report already says "an artifact is
      not a finding"; this is a case where the artifact is not even an
      artifact. Decide whether to set `ASAN_OPTIONS=detect_leaks=0` for these
      slices or to name leak-at-exit artifacts differently, but they should
      not be called `crash-`.

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
- [ ] **Cadence.** Currently push-to-main plus manual. Nightly later, as part
      of something bigger.

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

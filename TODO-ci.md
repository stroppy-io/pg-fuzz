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

- [ ] **`scripts/smoke.sh` green.** The pipeline end to end with the budgets
      turned down: campaign (sealed, rounds, deadline) → gates → report →
      index → bundle → census → inventory → breakdown. Its first run failed
      four steps and found three real things (a wrong flag in my script, the
      pin refusing a moved branch, `breakdown` exiting 2 on an empty workspace,
      which is correct and the script had to accept). Re-running.
- [ ] **`.github/workflows/sweep.yml` has never executed.** This is the largest
      open risk on this page. It is a 10-item matrix (pg16–19 + master ×
      address/undefined) and nothing has run it, here or on GitHub. `act`
      cannot: the oss-fuzz build needs docker inside the runner container.
- [ ] **The disk arithmetic is from this host, not a runner.** ~8.5 GB per item
      against ~14 GB is measured locally (base-builder 3.15 GB, project layers
      ~0.3, shallow clone ~250 MB, export ~2.6 GB, address build 1.5 GB). It
      has not been observed on a GitHub runner.
- [ ] **Artifact upload paths are guesses.** The globs for reproducers, series,
      samples and build logs have never matched anything in a real run.

## Left to build

- [ ] **Make `sweep.yml` call `scripts/smoke.sh`**, as `ci.yml` calls
      `ci.sh`. It currently inlines the steps, which is the same
      two-statements-of-one-fact problem that made the Go version skew.
- [ ] **A coverage SHAPE check.** Magnitude is a time-function and not worth
      chasing in a smoke run; shape is constant and worth checking every time.
      Every coverage defect fixed this week was a shape defect — `-measure` and
      `-union` reading different directories, the union's anchor binary, the
      per-component export having readers and no writer. One coverage-sanitizer
      item that measures a single target and asserts the summary carries all
      four counters and the union merges the profiles just written.
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

- [ ] README contributing section.
- [ ] Push. 101 commits sit on local `main`; `gh` is authenticated now, the
      remote has never been pushed to from here, and a force-push over
      pre-squash history needs a deliberate decision.

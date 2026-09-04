#!/usr/bin/env bash
#
# THE WHOLE PIPELINE, WITH THE BUDGETS TURNED DOWN.
#
# Not a fuzzing run. The purpose is to find out whether a script or a function
# is botched BEFORE somebody commits ten or twenty hours of machine time to a
# real campaign -- and the only way to know that is to run the same code path
# first, cheaply.
#
# So this is a miniature campaign, not a bare sweep: it seals, rounds, gates,
# ratchets, reports, bundles and indexes exactly as an overnight run does, with
# per-target budgets of seconds. A bare sweep exercises about a third of that
# and leaves the manifest, the rounds, the gate wiring, the report and the
# bundle to be discovered broken at hour nineteen.
#
#   scripts/smoke.sh <workspace> [seconds-per-target]
#
# The workflow calls this and nothing else, so what runs in CI is what runs
# here.
set -uo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 2
WS=${1:?usage: scripts/smoke.sh <workspace> [seconds-per-target]}
SECS=${2:-8}

# ENOUGH CLOCK FOR TWO COMPLETE ROUNDS, which is not the same as "short".
#
# round-complete is one of the gates under test, and a campaign too short to
# finish a 23-target round makes it fire every time -- a gate that always fails
# tells you nothing, which is the same defect as one that never does.
#
# The arithmetic: 21 targets at $SECS, plus spi_query at 150s and simple_query
# at 200s, is about nine minutes a round. Two rounds fit in 0.35h, and two is
# the minimum that exercises rotation and the round boundary rather than just
# the first pass.
HOURS=${HOURS:-0.35}
SLUG=${PGFUZZ_SMOKE_SLUG:-smoke}
OUT=${PGFUZZ_SMOKE_OUT:-${TMPDIR:-/tmp}/pgfuzz-smoke}

command -v pgfuzz >/dev/null 2>&1 || PATH="$PWD/go/bin:$PATH"
export PATH
mkdir -p "$OUT"

FAILED=()
step() {
	local name=$1; shift
	printf '\n\033[1m== %s\033[0m\n' "$name"
	if "$@"; then printf '   \033[32mok\033[0m   %s\n' "$name"
	else printf '   \033[31mFAIL\033[0m %s\n' "$name"; FAILED+=("$name"); fi
}

# A CAMPAIGN, because that is the code path a long run uses. Sealed so the
# corpus is copied and the manifest written; two rounds' worth of clock so
# rotation and the per-round gate hook both run; on-deadline cut so the
# deadline path is exercised rather than assumed.
# -no-pin: a smoke run is not a campaign, and the pin exists to make a campaign
# reproducible. Five moving branches drift constantly, so enforcing pins here
# makes the run red for a reason that has nothing to do with the code.
# THE TUNED BUDGETS STAY ON, and that costs about six minutes a round.
#
# I tried turning them off, on the reasoning that a run measuring nothing
# should not pay for spi_query's 150 seconds and simple_query's 200. Skipping
# them CREATES the condition the replay gate exists to catch: at eight seconds
# simple_query spends the whole slice replaying its corpus and mutates nothing,
# which is precisely what those floors are for. The budget and the gate encode
# one fact from opposite sides, and a smoke run that disables half of it is
# not exercising the real code path.
step "campaign" pgfuzz campaign -slug "$SLUG" -sealed -w "$WS" -no-pin \
	-hours "${HOURS:-0.35}" -time "$SECS" -jobs 2 -on-deadline cut -profile smoke

# THE GATES, over the campaign's OWN logs. -logs is the flag that was missing
# for the whole of this port's life: a sealed campaign writes under the slug,
# and pointing the gates at the workspace judges an earlier run.
CAMP=$(pgfuzz ws 2>/dev/null >/dev/null; echo "${PGFUZZ_WS:-$HOME/pgfuzz}/campaigns/$SLUG/ws/$WS")
# A FLOOR PROPORTIONAL TO THE SLICE.
#
# The production floor is 10,000 executions, set for a real slice. An
# eight-second one genuinely starves against it -- 8,544 on binary_recv in the
# run that found this -- so the default floor would make every smoke run red
# for the one reason that carries no information.
#
# Not zero, though: a target that executed NOTHING must still fail, because
# that is the failure this gate exists for. 100 is below anything that ran and
# above anything that did not.
step "gates" pgfuzz gate -w "$WS" -logs "$CAMP" -since 24h -floor 100

# THE DOCUMENTS. A report or a bundle that cannot be produced is discovered at
# the end of a campaign, which is the worst possible time to find out.
step "report"    pgfuzz report -slug "$SLUG" -html "$OUT/report.html" -md "$OUT/report.md"
step "index"     pgfuzz index  -slug "$SLUG" -o "$OUT/index.html"
# THE BUNDLE IS CHECKED BY WHAT IT PRODUCED, not by its exit code.
#
# It exits non-zero when a stage failed, and stages legitimately fail here: a
# fresh ratchet profile has no baseline to ship, and the smoke campaign has no
# coverage. Both are recorded in the manifest as absent, which is the correct
# behaviour and not a reason to call the pipeline broken. What matters is that
# a bundle came out at all.
step "bundle" bash -c '
	pgfuzz bundle -slug "$0" -out "$1" -no-corpus
	ls "$1"/*.tar.gz >/dev/null 2>&1 || { echo "no bundle was produced"; exit 1; }
' "$SLUG" "$OUT/bundle"

# THE THINGS THAT READ A FINISHED RUN.
step "census"    pgfuzz census    -w "$WS" -o "$OUT/census" -summary
step "inventory" pgfuzz inventory -w "$WS"
# NOTHING TO BREAK DOWN IS NOT A FAILURE HERE. breakdown exits 2 when a
# workspace has no attributable frames, which is correct -- an empty table and
# "no component was involved" are different answers, and the project's rule is
# that absence is never a pass. But a smoke run is asking whether the command
# RUNS, and a healthy workspace has no crashes to attribute.
step "breakdown" bash -c 'pgfuzz breakdown -w "$0" || [ $? -eq 2 ]' "$WS"

echo
if [ ${#FAILED[@]} -eq 0 ]; then
	printf '\033[32msmoke green\033[0m  (%s, %ss per target)\n' "$WS" "$SECS"
	exit 0
fi
printf '\033[31m%d step(s) failed:\033[0m %s\n' "${#FAILED[@]}" "${FAILED[*]}"
exit 1

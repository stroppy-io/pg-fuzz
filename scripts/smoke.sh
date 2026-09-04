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
step "campaign" pgfuzz campaign -slug "$SLUG" -sealed -w "$WS" -no-pin \
	-hours 0.12 -time "$SECS" -jobs 2 -on-deadline cut -profile smoke

# THE GATES, over the campaign's OWN logs. -logs is the flag that was missing
# for the whole of this port's life: a sealed campaign writes under the slug,
# and pointing the gates at the workspace judges an earlier run.
CAMP=$(pgfuzz ws 2>/dev/null >/dev/null; echo "${PGFUZZ_WS:-$HOME/pgfuzz}/campaigns/$SLUG/ws/$WS")
step "gates" pgfuzz gate -w "$WS" -logs "$CAMP" -since 24h

# THE DOCUMENTS. A report or a bundle that cannot be produced is discovered at
# the end of a campaign, which is the worst possible time to find out.
step "report"    pgfuzz report -slug "$SLUG" -html "$OUT/report.html" -md "$OUT/report.md"
step "index"     pgfuzz index  -slug "$SLUG" -o "$OUT/index.html"
step "bundle"    pgfuzz bundle -slug "$SLUG" -out "$OUT/bundle" -no-corpus

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

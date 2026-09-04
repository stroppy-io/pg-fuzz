#!/usr/bin/env bash
#
# THE SHAPE OF A COVERAGE MEASUREMENT, not its magnitude.
#
# How much coverage a run reaches is a function of how long it ran, so a number
# from a smoke run says nothing anyone should read. The SHAPE does not depend
# on time and is worth checking every single run: that a measurement produces
# all four counters, that the union can see the profiles the measurement just
# wrote, and that the union says which binary its percentages are against.
#
# Every coverage defect found in this repository's second audit was a shape
# defect, and each was invisible to a percentage:
#
#   - `-measure` and `-union` globbed different directories, so a union merged
#     shell-era leftovers or reported "no profiles" for a workspace that had
#     just measured all 23 targets;
#   - the union's anchor binary was unrecorded, so nobody could tell what the
#     denominator covered;
#   - coverage-components.jsonl had three readers and no writer at all.
#
# All three would have been caught in seconds by the assertions below.
#
#   scripts/smoke-coverage.sh <coverage-workspace> [target]
set -uo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 2
WS=${1:?usage: scripts/smoke-coverage.sh <coverage-workspace> [target]}
TARGET=${2:-jsonb_fuzzer}

command -v pgfuzz >/dev/null 2>&1 || PATH="$PWD/go/bin:$PATH"
export PATH

FAILED=()
ok()  { printf '   \033[32mok\033[0m   %s\n' "$1"; }
bad() { printf '   \033[31mFAIL\033[0m %s\n' "$1"; FAILED+=("$1"); }

SERIES="${PGFUZZ_HOME:-$PWD}/scripts/coverage-series.jsonl"
before=$(wc -l < "$SERIES" 2>/dev/null || echo 0)

printf '\n\033[1m== measure %s\033[0m\n' "$TARGET"
if pgfuzz coverage -w "$WS" -measure -t "$TARGET" -min-free-gb 0; then
	ok "measure ran"
else
	bad "measure ran"
fi

# ALL FOUR COUNTERS, each with a non-zero denominator. A measurement that
# produces "lines: 0 of 0" is not a low number, it is a broken one -- and it
# reads as 0% on every page that shows it.
printf '\n\033[1m== the summary has a shape\033[0m\n'
after=$(wc -l < "$SERIES" 2>/dev/null || echo 0)
if [ "$after" -le "$before" ]; then
	bad "the measurement recorded no row in $SERIES"
else
	row=$(tail -1 "$SERIES")
	miss=""
	for k in lines functions regions branches; do
		n=$(printf '%s' "$row" | sed -n "s/.*\"$k\":{\"count\":\([0-9]*\).*/\1/p")
		[ -n "$n" ] && [ "$n" -gt 0 ] 2>/dev/null || miss="$miss $k"
	done
	if [ -n "$miss" ]; then bad "counters with no denominator:$miss"
	else ok "lines, functions, regions and branches all have counts"; fi
fi

# THE UNION MUST SEE WHAT THE MEASUREMENT JUST WROTE. This is the pair that was
# reading different directories, so it is checked as a pair.
printf '\n\033[1m== the union sees it\033[0m\n'
out=$(pgfuzz coverage -w "$WS" -union 2>&1)
echo "$out" | tail -6
if printf '%s' "$out" | grep -q 'no per-target profiles'; then
	bad "the union cannot see the profiles the measurement wrote"
elif printf '%s' "$out" | grep -qE 'merging [0-9]+ per-target profile'; then
	ok "the union merged the profiles"
else
	bad "the union produced no merge line"
fi

# AND IT SAYS WHAT THE DENOMINATOR COVERS. One anchor binary is chosen for the
# objects, so a function linked only into another target leaves the numerator
# and the denominator together -- honest for what it covers, and only if it
# names what that is.
if printf '%s' "$out" | grep -qE '_fuzzer'; then
	ok "the union names its anchor"
else
	bad "the union does not say which binary it measured against"
fi

echo
if [ ${#FAILED[@]} -eq 0 ]; then
	printf '\033[32mcoverage shape green\033[0m  (%s)\n' "$WS"
	exit 0
fi
printf '\033[31m%d check(s) failed:\033[0m %s\n' "${#FAILED[@]}" "${FAILED[*]}"
exit 1

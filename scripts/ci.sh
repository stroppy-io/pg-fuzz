#!/usr/bin/env bash
#
# THE WHOLE OF CI, RUNNABLE HERE.
#
# The workflow calls this script and nothing else, so "green locally" and
# "green on GitHub" are the same claim rather than two that drift. The version
# skew this replaced is the argument: .github/workflows/ci.yml pinned Go 1.24
# while go/go.mod declared 1.27, so every push would have failed on a
# toolchain that cannot build the module -- two statements of one fact, which
# is the defect this repository's whole audit was about.
#
#   scripts/ci.sh          run every job
#   scripts/ci.sh test     run one: test | wiring | harness
#
# Exit 0 only if everything a reviewer would check passes.
set -uo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 2
FAILED=()

say()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
ok()   { printf '   ok   %s\n' "$*"; }
bad()  { printf '   FAIL %s\n' "$*"; FAILED+=("$1"); }

# The toolchain the module asks for, not a number written twice.
need_go() {
	if command -v go >/dev/null 2>&1; then return 0; fi
	# The host keeps it here and off PATH; see the note in AGENTS.md.
	if [ -x "$HOME/.local/go/bin/go" ]; then
		export PATH="$PATH:$HOME/.local/go/bin"
		return 0
	fi
	echo "go not found -- install it or add it to PATH" >&2
	exit 2
}

job_test() {
	say "test"
	# NO THIRD-PARTY DEPENDENCIES, deliberately: a binary handed to a vendor so
	# they can confirm a defect must not need a module proxy to build.
	if grep -qE '^\s*require' go/go.mod; then
		bad "go.mod has grown a dependency"
		grep -nE '^\s*require' -A5 go/go.mod
	else ok "no third-party dependencies"; fi

	( cd go && go build ./... ) && ok "build" || bad "build"
	( cd go && go vet ./... )   && ok "vet"   || bad "vet"

	local unformatted
	unformatted=$(cd go && gofmt -l ./cmd ./internal)
	if [ -n "$unformatted" ]; then
		bad "gofmt"; echo "$unformatted"
	else ok "gofmt"; fi

	( cd go && go test ./... ) >/dev/null && ok "go test" || {
		bad "go test"; ( cd go && go test ./... ) | grep -v '^ok' | head -20
	}

	# The campaign appends the series from several goroutines and the progress
	# writer is shared. Neither would fail loudly if it raced.
	( cd go && go test -race ./internal/campaign/ ./internal/fuzz/ ) >/dev/null \
		&& ok "go test -race" || bad "go test -race"
}

# THE CHECK THAT WOULD HAVE CAUGHT THE AUDIT'S FINDINGS: a package that
# compiles and is imported by nothing is the exact shape of every gap.
job_wiring() {
	say "wiring"
	local fail=0 d pkg
	for d in go/internal/*/; do
		pkg="pgfuzz/internal/$(basename "$d")"
		case "$pkg" in *assets) continue ;; esac
		grep -rq "\"$pkg\"" --include='*.go' go/cmd go/internal || {
			echo "   no caller for $pkg"; fail=1; }
	done
	[ $fail = 0 ] && ok "every internal package has a caller" \
		|| bad "an internal package has no caller"

	local bin cmds c
	bin=$(mktemp) || exit 2
	( cd go && go build -o "$bin" ./cmd/pgfuzz ) || { bad "build for wiring"; return; }
	cmds=$("$bin" 2>&1 | sed -n 's/^  pgfuzz \([a-z-]*\).*/\1/p' | sort -u)
	rm -f "$bin"
	if [ -z "$cmds" ]; then bad "no commands found in the usage text"; return; fi
	fail=0
	for c in $cmds; do
		grep -q "case \"$c\":" go/cmd/pgfuzz/main.go \
			|| { echo "   usage documents '$c' but nothing dispatches it"; fail=1; }
	done
	[ $fail = 0 ] && ok "every documented command is reachable ($(echo "$cmds" | wc -w))" \
		|| bad "a documented command is unreachable"
}

# The harnesses are C compiled inside OSS-Fuzz's image, which this does not
# have. A syntax check still catches the class of mistake that survives review.
job_harness() {
	say "harness"
	if ! command -v clang >/dev/null 2>&1; then
		echo "   skipped: clang not installed"
		return
	fi
	local fail=0 f err
	err=$(mktemp) || exit 2
	for f in project/fuzzer/*.c; do
		clang -fsyntax-only -I project/fuzzer "$f" 2>"$err" || {
			# MISSING POSTGRESQL HEADERS ARE EXPECTED; anything else is real.
			#
			# The obvious spelling of this is wrong, and was: `grep -qvE
			# "file not found"` succeeds whenever ANY line fails to match, and
			# clang always prints the offending source line and a caret and
			# "1 error generated." So every harness looked like a real parse
			# error and this job could never pass.
			#
			# Only diagnostic lines count, and only ones that are not about a
			# header this machine does not have.
			if grep -E "(error|warning):" "$err" |
				grep -qvE "file not found|no such file"; then
				echo "   == $f"; head -5 "$err"; fail=1
			fi
		}
	done
	rm -f "$err"
	[ $fail = 0 ] && ok "harness sources parse" || bad "a harness source does not parse"
}

# Go is needed by two of the three jobs. The harness job needs clang and not
# Go, and requiring it there fails a job that would otherwise pass -- which is
# what a CI job asking for a tool it does not use costs.
case "${1:-all}" in
	test)    need_go; job_test ;;
	wiring)  need_go; job_wiring ;;
	harness) job_harness ;;
	all)     need_go; job_test; job_wiring; job_harness ;;
	*)       echo "usage: scripts/ci.sh [all|test|wiring|harness]" >&2; exit 2 ;;
esac

echo
if [ ${#FAILED[@]} -eq 0 ]; then
	printf '\033[32mCI green\033[0m\n'
	exit 0
fi
printf '\033[31m%d check(s) failed:\033[0m %s\n' "${#FAILED[@]}" "${FAILED[*]}"
exit 1

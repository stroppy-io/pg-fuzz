#!/bin/bash -eux
# Copyright 2020 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################
#
# Local variant of projects/postgresql/build.sh.  Differences, all forced by the
# source tree being a bind-mounted local checkout rather than a fresh clone of
# upstream master:
#
#   * the source tree has no .git, and the patches were written against master,
#     so they are applied with "patch -F" instead of "git apply";
#   * the bind mount replaces the image's directory, so "bld" is created here;
#   * the seed corpus is built from the local tree's regress SQL, and named per
#     fuzz target so libFuzzer/ClusterFuzz actually picks it up;
#   * ownership of the bind-mounted tree and of $OUT is restored to the host
#     user (uid 1000) at the end, so the workspace stays writable outside the
#     container.

# ---------------------------------------------------------------------------
# Make signed-integer-overflow RECOVERABLE under UndefinedBehaviorSanitizer.
#
# OSS-Fuzz compiles the undefined build with
# "-fno-sanitize-recover=...,signed-integer-overflow,..." which makes every
# signed overflow ABORT the process.  On this project that costs five targets
# their entire round: simple_query, scalar_types, datetime, network and
# binary_recv each die once per corpus replay on four already-catalogued sites
#
#     numutils.c:601      negation of INT32_MIN      pg_strtoint32_safe
#     numutils.c:720      negation of INT64_MIN      pg_strtoint64_safe
#     timestamp.c:2016    date * USECS_PER_DAY       tm2timestamp
#     inet_net_pton.c:183 accumulating an octet      inet_cidr_pton_ipv4
#
# and get ~196 executions instead of hundreds of thousands, on ten of the
# sixteen UBSan workspaces.
#
# PostgreSQL builds with -fwrapv, so signed overflow is DEFINED to wrap in the
# binaries they ship.  These are wrong-result and bypassed-range-check bugs, not
# memory corruption -- FINDINGS/README.md has carried that qualifier for two
# weeks.  Aborting on them buys nothing and costs the round.
#
# WHY NOT A SUPPRESSIONS FILE
# ===========================
# It cannot work here.  A non-recoverable check calls __ubsan_handle_*_abort,
# which never consults the suppressions list -- the trap is compiled in, so no
# runtime option can soften it.  Recoverable is the only lever, and it has to be
# pulled at build time.
#
# WHAT THIS DOES NOT DO
# =====================
# It does not stop detecting signed overflow.  Every site is still reported, on
# stderr, with its DEDUP_TOKEN; UBSan prints each unique source location once
# per process, so the report survives without the per-input flood that cost
# simple_query 99.8% of its throughput on 2026-08-17.
#
# The reports are then judged by scripts/check-ubsan.sh against a committed
# baseline: a site nobody has accepted FAILS the round.  Detection is unchanged;
# what changed is that a known, benign, documented site no longer kills the
# target that found it.
#
# Every other check keeps its abort.  Only signed-integer-overflow is moved, and
# only because -fwrapv makes it defined in the builds PostgreSQL ships.
if [ "${SANITIZER:-}" = "undefined" ]; then
	echo "==> UBSan: making signed-integer-overflow recoverable (see build.sh)" >&2
	for _v in CFLAGS CXXFLAGS; do
		_cur=${!_v}
		# Drop it from the -fno-sanitize-recover list only. It stays in
		# -fsanitize=, so it is still checked and still reported.
		# Two passes: the entry can sit mid-list (",signed-...") or first
		# ("=signed-...,"). Note ",signed-integer-overflow" cannot match inside
		# "unsigned-integer-overflow" -- the character before "signed" there is
		# "n", not a comma -- so the unsigned check is left alone. Verified
		# against the real flag string before this shipped.
		_new=$(printf '%s' "$_cur" \
			| sed -E ':a;s/(-fno-sanitize-recover=[^ ]*),signed-integer-overflow/\1/;ta' \
			| sed -E ':b;s/(-fno-sanitize-recover=)signed-integer-overflow,/\1/;tb')
		export "$_v"="$_new"
	done
	# Fail loudly rather than silently building the old way: if the flag string
	# ever changes shape, a build that still aborts on overflow would look
	# identical to one that does not, and the five starved targets would come
	# back with no explanation.
	case "$CFLAGS" in
		*-fno-sanitize-recover=*signed-integer-overflow*)
			echo "ERROR: signed-integer-overflow still non-recoverable in CFLAGS" >&2
			echo "  CFLAGS=$CFLAGS" >&2
			exit 1 ;;
	esac
	case "$CFLAGS" in
		*signed-integer-overflow*) : ;;   # still in -fsanitize=, good
		*) echo "ERROR: signed-integer-overflow vanished from CFLAGS entirely" >&2
		   echo "  detection would be OFF, which is worse than the problem" >&2
		   echo "  CFLAGS=$CFLAGS" >&2
		   exit 1 ;;
	esac
	echo "==> CFLAGS now: $CFLAGS" >&2
fi

HOST_UID=1000
HOST_GID=1000

# Hand the bind-mounted source tree and $OUT back to the host user however we
# exit.  Doing this only on success is a trap: a build that dies halfway leaves
# root-owned files in the workspace, and the next run then cannot even delete
# the tree to start over.
trap 'chown -R $HOST_UID:$HOST_GID $SRC/postgres $OUT 2>/dev/null || true' EXIT

# Apply a patch idempotently.  "patch -N" skips hunks that are already applied
# but still exits non-zero, which under "set -e" would abort a rebuild against
# a source tree left over from a previous run.  Tolerate that, then assert that
# the patch really did land -- a silently unpatched tree builds fine and then
# behaves subtly wrong at fuzz time, which is far worse than a build failure.
# The OrioleDB flavor: pgfuzz exports the extension into orioledb/ inside the
# PostgreSQL tree, because helper.py bind-mounts exactly one source directory.
if [ -d orioledb ] && [ -f orioledb/orioledb.control ]; then
	ORIOLEDB=1
	# OrioleDB refuses to build against any PostgreSQL but the exact commit
	# pinned in its .pgtags, and identifies the tree by the commit hash its
	# configure read out of git.  We build from a `git archive` export, which
	# has no .git, so pgfuzz records the hash in .pgfuzz-ref for us; without
	# this the check sees the Makefile's fallback value of 1 and aborts.
	PGSHA=$(awk '{print $3}' .pgfuzz-ref 2>/dev/null)
	[ -n "$PGSHA" ] || { echo "ERROR: no PostgreSQL commit in .pgfuzz-ref" >&2; exit 1; }

	# .pgtags NOW NAMES A TAG, NOT A COMMIT, and the check compares against
	# whichever it holds. Upstream changed the format:
	#
	#	17: 1e13fa1993dd9b1b867e6362c1f1930849e8be7b   (what it used to say)
	#	17: patches17_21                               (what it says now)
	#
	# check_patchset_version.py splits "patches17_21" on the underscore and
	# expects the numeric half, so passing the commit hash -- which is what
	# this did, and what worked against the old format -- now fails every
	# OrioleDB build with
	#
	#	Wrong orioledb patchset version: expected 21, got e1ec37301414...
	#
	# The ref field of .pgfuzz-ref is what the tree was exported AT, so when
	# that is a patches tag the version is simply its numeric half. Taken from
	# the export rather than re-read out of .pgtags on purpose: reading the
	# expected value and handing it back would satisfy the check by
	# construction and assert nothing about the tree.
	PGREF=$(awk '{print $1}' .pgfuzz-ref 2>/dev/null)
	case "$PGREF" in
		patches*_*) ORIOLEDB_PATCHSET=${PGREF##*_} ;;
		*)          ORIOLEDB_PATCHSET=$PGSHA ;;
	esac
	echo "build.sh: OrioleDB flavor, PostgreSQL $PGSHA, patchset $ORIOLEDB_PATCHSET (from $PGREF)"
else
	ORIOLEDB=0
	# Read it here too. cmd_sync writes .pgfuzz-ref for *every* workspace, but
	# this was only parsed in the orioledb branch, so every postgres-flavor
	# build recorded "pg_ref_sha": "unknown" -- a build record that cannot tie
	# itself back to a commit, which is exactly what a finding needs at
	# consolidation.
	PGSHA=$(awk '{print $3}' .pgfuzz-ref 2>/dev/null)
fi

apply_patch() {
	local diff=$1 marker=$2 file=$3
	local out files f rejs=""

	# Every file this diff touches, so we can verify ALL of them -- not just the
	# single marker file the caller named. A diff that patches two files and
	# fails the second used to pass silently: the marker check only looked at
	# the first. That is exactly how a malformed elog.c hunk shipped in
	# add_fuzzers.diff (whose marker is in postgres.c) while apply_patch
	# reported success and the fix quietly never applied.
	files=$(sed -n 's,^+++ b/,,p' "$diff" | sed 's/\t.*//')

	# Clear stale rejects so the post-check only sees this run's.
	for f in $files; do rm -f "$f.rej"; done

	# -N makes an already-applied hunk exit non-zero (idempotent rebuilds), so
	# exit status alone cannot tell "already applied" from "failed to apply".
	# Judge instead by what patch says and by whether it left any .rej.
	out=$(patch -p1 -F5 -l -N --no-backup-if-mismatch -i "$diff" 2>&1) || true
	printf '%s\n' "$out"

	if printf '%s' "$out" | grep -qiE 'malformed patch|unexpected end of file|can.?t find file|No file to patch'; then
		echo "ERROR: $diff is malformed or does not match the tree (see above)" >&2
		exit 1
	fi
	if printf '%s' "$out" | grep -qiE 'hunk[s]? +FAILED|hunk[s]? +ignored'; then
		echo "ERROR: $diff had one or more rejected hunks" >&2
		exit 1
	fi
	for f in $files; do [ -e "$f.rej" ] && rejs="$rejs $f.rej"; done
	if [ -n "$rejs" ]; then
		echo "ERROR: $diff left rejects:$rejs" >&2
		exit 1
	fi

	# Positive confirmation: the caller's marker is present, and every file the
	# diff claims to produce actually exists.
	if [ -n "$marker" ] && ! grep -q "$marker" "$file"; then
		echo "ERROR: $diff applied clean but marker '$marker' is absent from $file" >&2
		exit 1
	fi
	for f in $files; do
		[ -e "$f" ] || { echo "ERROR: $diff should have produced $f but it is missing" >&2; exit 1; }
	done
}

# Apply diff for fuzzers.  Patches were generated against master; -F5 absorbs
# the context drift against the checked-out branch.
mkdir -p src/backend/fuzzer
cp -r $SRC/fuzzer/. src/backend/fuzzer/
apply_patch $SRC/add_fuzzers.diff fuzzer_first_run src/backend/tcop/postgres.c

# Genuine PostgreSQL correctness fix, kept separate from the fuzzer plumbing so
# it can be reported upstream as-is.  The config lexer's STRING rule matches an
# embedded NUL, but DeescapeQuotedString() measures the token with strlen();
# the value is then mis-parsed -- an Assert in a cassert build, a silent
# truncation in production.  This rejects a NUL-bearing value as a parse error
# where yyleng is still correct.  config_file_fuzzer found it (see
# FINDINGS/config-file-nul-deescape); with this applied the target fuzzes the
# whole parser instead of dying on one signature -- no harness-side suppression.
# guc-file.c is generated from guc-file.l by flex during the build, so patching
# the .l is enough.
apply_patch $SRC/guc_file_nul.diff "cannot meaningfully hold" src/backend/utils/misc/guc-file.l

# Seed corpus: the regression-test SQL of *this* tree.  Named per target so the
# OSS-Fuzz convention <target>_seed_corpus.zip applies.
rm -f $SRC/simple_query_fuzzer_seed_corpus.zip
zip -q -j $SRC/simple_query_fuzzer_seed_corpus.zip src/test/regress/sql/*.sql

# Seed corpus for extension_funcs_fuzzer.  Its input is THREE control bytes -- a
# 16-bit little-endian function selector, then the NULL bitmap -- followed by
# \x1f-separated argument text.  An empty starting corpus would make libFuzzer
# discover that layout by chance before it can call anything at all: with a
# three-byte minimum, most random inputs are rejected before an argument is ever
# built.
#
# The selector used to be one byte, which capped this target at 256 reachable
# functions however many were discovered; seeds covered selectors 0..31 only,
# which was adequate when an extension set meant 154 functions and is not now
# that one plugin declares 582.
#
# So the seeds spread across the selector space instead of clustering at the
# bottom: 0..31 densely, since low indices exist in every workspace, then in
# strides of 32 up to 2047.  Selection is modulo nfuncs, so a stride that
# overshoots a small extension set still lands somewhere useful rather than
# being wasted.
rm -rf /tmp/extfuncs_seeds
mkdir -p /tmp/extfuncs_seeds
python3 - <<'PY'
vals = [b"abc", b"ABC", b"abc\x1fABC", b"ABC\x1fabc", b"\x1f", b"1\x1f2",
        b"0", b"-1", b"aaaaaaaaaaaaaaaa", b"\xd0\xbf\xd1\x80\xd0\xb8",
        b"a\x1f", b"\x1fa", b"true\x1ffalse", b" \x1f ", b"%\x1f_"]
sels = sorted(set(list(range(32)) + [i * 32 for i in range(1, 64)]))
n = 0
for sel in sels:
    for nullmap in (0, 1, 3):
        for v in vals:
            with open("/tmp/extfuncs_seeds/s%05d" % n, "wb") as f:
                f.write(bytes([sel & 0xFF, (sel >> 8) & 0xFF, nullmap]) + v)
            n += 1
print("build.sh: %d extension_funcs seeds over %d selectors" % (n, len(sels)))
PY
rm -f $SRC/extension_funcs_fuzzer_seed_corpus.zip
zip -q -j $SRC/extension_funcs_fuzzer_seed_corpus.zip /tmp/extfuncs_seeds/*

# Change permission for fuzzers.  -o -u 1000 keeps the bind-mounted files owned
# by the host user rather than by a container-only uid.
useradd -o -u $HOST_UID -m fuzzuser || true
mkdir -p bld
chown -R fuzzuser .

cd bld

# Use the distribution's ICU (libicu-dev, installed in the Dockerfile) for both
# the uninstrumented "createdb" build and the instrumented fuzzer build, so that
# headers, shared libraries and static libraries are all the same version.
# --enable-cassert on *both* configures, deliberately.
#
# PostgreSQL's Assert() calls are its own internal consistency checks, and
# compiling them out throws away the cheapest bug detector in the tree: they
# catch corrupted node trees, broken invariants and impossible states that a
# memory sanitizer cannot see, and they report at the point of violation rather
# than wherever the damage later surfaces.  (The hba harness bug presented as a
# mangled SEGV in palloc0; an assert build would have said
# "Assert(tokenize_context)" immediately.)
#
# Both builds, not just the instrumented one: orioledb.so is compiled against
# the uninstrumented tmp_install's headers and then loaded into the
# instrumented backend, so USE_ASSERT_CHECKING has to match on both sides or
# the two disagree about struct layouts.
# PGFUZZ_SERVER_ASAN=1 builds the *server* tree with the sanitizer and with
# asserts OFF, which is what it takes to answer "is this assert hiding a real
# memory error?".  With asserts on, execution stops at the Assert and never
# reaches the code under suspicion; with them off and no sanitizer, an overrun
# is silent.  Only the combination is decisive.  The default is unchanged:
# uninstrumented, asserts on.
# Two independent knobs, because they answer different questions:
#
#   PGFUZZ_SERVER_CASSERT=0  asserts off, still uninstrumented gcc.  This is
#       what shows what a *release* build does at a site where an assertion
#       currently stops execution -- e.g. whether an unbounded memcpy after an
#       assert actually overruns.  Cheap and uses the known-good build path.
#
#   PGFUZZ_SERVER_ASAN=1     additionally sanitize the server tree.  Stronger
#       detection, but the sanitized standalone backend currently dies during
#       initdb's post-bootstrap step ("child process exited with exit code 1",
#       no output), so this path does not work yet.  Left in place, off by
#       default, rather than deleted -- the diagnosis is worth finishing.
if [ "${PGFUZZ_SERVER_ASAN:-0}" = 1 ]; then
	echo "==> server tree: sanitizer ON, asserts OFF (PGFUZZ_SERVER_ASAN=1)" >&2
	su fuzzuser -c "CC='$CC' CXX='$CXX' CFLAGS='$CFLAGS' CXXFLAGS='$CXXFLAGS' ../configure --disable-cassert"
elif [ "${PGFUZZ_SERVER_CASSERT:-1}" = 0 ]; then
	echo "==> server tree: uninstrumented gcc, asserts OFF (PGFUZZ_SERVER_CASSERT=0)" >&2
	CC="" CXX="" CFLAGS="" CXXFLAGS="" su fuzzuser -c "../configure --disable-cassert"
else
	CC="" CXX="" CFLAGS="" CXXFLAGS="" su fuzzuser -c "../configure --enable-cassert"
fi

PGBIN=$PWD/tmp_install/usr/local/pgsql/bin

cd src/backend/fuzzer
# LC_ALL=C: dbfuzz runs initdb with no --locale, and OrioleDB tables only
# support the C, POSIX and ICU collations.
#
# Under PGFUZZ_SERVER_ASAN the server tools are sanitized, and ASan's exit-time
# leak check then fails initdb -- which allocates and exits without freeing, as
# a short-lived program reasonably may -- taking temp-install down with it.
# Leak detection is not what this build mode is for: it exists to catch the
# out-of-bounds write, so turn the leak check off and leave the rest on.
SERVER_ASAN_ENV=""
if [ "${PGFUZZ_SERVER_ASAN:-0}" = 1 ]; then
	SERVER_ASAN_ENV="ASAN_OPTIONS=detect_leaks=0:detect_odr_violation=0:abort_on_error=1"
fi
# temp-install runs initdb and redirects its output into a log *inside* the
# build tree, so a failure here surfaces only as "Error 1" and the reason dies
# with the container.  Print those logs on failure rather than guessing -- two
# rebuilds were already spent guessing at this.
if ! LC_ALL=C su fuzzuser -c "$SERVER_ASAN_ENV make -j$(nproc) createdb"; then
	echo "=== createdb failed; temp-install logs follow ===" >&2
	for l in $PWD/../../../tmp_install/log/*.log; do
		[ -f "$l" ] || continue
		echo "--- $l" >&2
		tail -40 "$l" >&2
	done

	# temp-install installs the binaries and *then* runs initdb, so when initdb
	# is what failed the binaries are present and the step can be repeated by
	# hand.  Do that with the sanitizer told to report to stderr and be verbose:
	# initdb redirects its child's output into a log, which is how a sanitizer
	# report ends up invisible and the failure reads as a bare "exit code 1".
	PROBE_INITDB=$PWD/../../../tmp_install/usr/local/pgsql/bin/initdb
	if [ -x "$PROBE_INITDB" ]; then
		echo "=== re-running initdb directly, sanitizer output to stderr ===" >&2
		rm -rf /tmp/asan-probe
		su fuzzuser -c "ASAN_OPTIONS=detect_leaks=0:log_path=stderr:verbosity=1 \
			LD_LIBRARY_PATH=$PWD/../../../tmp_install/usr/local/pgsql/lib \
			$PROBE_INITDB -D /tmp/asan-probe --auth trust --no-sync \
			--no-instructions --lc-messages=C" >&2 2>&1 || true
	fi
	exit 1
fi

if [ "$ORIOLEDB" = 1 ]; then
	# Build and install the extension *after* createdb, not before.  createdb
	# depends on PostgreSQL's temp-install target, which starts with
	# `rm -rf tmp_install` -- so an extension installed earlier is silently
	# deleted again, and the server then refuses to start on a
	# shared_preload_libraries entry whose file no longer exists.
	su fuzzuser -c "make -C ../../../../orioledb -j$(nproc) USE_PGXS=1 PG_CONFIG=$PGBIN/pg_config ORIOLEDB_PATCHSET_VERSION=$ORIOLEDB_PATCHSET"
	su fuzzuser -c "make -C ../../../../orioledb USE_PGXS=1 PG_CONFIG=$PGBIN/pg_config ORIOLEDB_PATCHSET_VERSION=$ORIOLEDB_PATCHSET install"
	test -f "$PGBIN/../lib/orioledb.so" || { echo "ERROR: orioledb.so not installed" >&2; exit 1; }
	# The cluster exists now but knows nothing about OrioleDB.  Preload the
	# library and create the extension in the database the harnesses attach to.
	{
		echo "shared_preload_libraries = 'orioledb.so'"
		# $libdir is compiled in as the configure prefix,
		# /usr/local/pgsql/lib, and that path exists only in the *build*
		# container.  base-runner does not have it -- the tree is mounted at
		# /out/tmp_install instead -- so a fuzz target that reaches
		# process_shared_preload_libraries() cannot resolve 'orioledb.so' and
		# the backend dies before logging is up, silently, exit 1.
		#
		# The consequence was that no libFuzzer target ever loaded OrioleDB,
		# on any workspace, in any campaign: the four backend targets are the
		# only ones that call process_shared_preload_libraries() at all, and
		# for them the preload could never have succeeded.
		#
		# $libdir stays first so the build-time cluster below -- which runs
		# where the prefix does exist, and before /out/tmp_install has been
		# populated -- is unaffected.  PostgreSQL searches
		# dynamic_library_path for any library name without a directory
		# component, so one setting serves both environments.
		echo "dynamic_library_path = '\$libdir:/out/tmp_install/usr/local/pgsql/lib'"
		# Unix socket only, in a directory fuzzuser can write.  Setting these
		# in the config file rather than passing -o through `su -c` avoids a
		# layer of quoting that silently mangles an empty -h argument.
		echo "listen_addresses = ''"
		echo "unix_socket_directories = '/tmp'"
	} >> temp/data/postgresql.conf

	chown -R fuzzuser temp

	# The binaries in tmp_install carry an rpath of the *installed* prefix
	# (/usr/local/pgsql/lib), which does not exist, so they need
	# LD_LIBRARY_PATH.  It has to be set inside the shell su starts, not in our
	# environment: su is setuid and glibc's loader drops LD_LIBRARY_PATH across
	# a setuid exec.  (The same trap is documented at the top of this file for
	# the ICU build.)
	PGLIB=$PWD/../../../tmp_install/usr/local/pgsql/lib
	as_fuzzuser() { su fuzzuser -c "LD_LIBRARY_PATH=$PGLIB $*"; }

	if ! as_fuzzuser "$PGBIN/pg_ctl -D temp/data -w -l temp/oriole.log start"; then
		echo "=== server failed to start with orioledb preloaded; log follows ===" >&2
		cat temp/oriole.log >&2 || true
		exit 1
	fi
	# Enable the extension in dbfuzz -- the database the harnesses attach to
	# (see InitPostgres("dbfuzz", ...) in fuzzer_initialize.c) -- and prove it
	# actually works before spending a build on it: ON_ERROR_STOP turns any of
	# these into a build failure, and creating a table USING orioledb exercises
	# the table access method rather than just the CREATE EXTENSION record.
	as_fuzzuser "$PGBIN/psql -h /tmp -d dbfuzz -v ON_ERROR_STOP=1 \
		-c 'CREATE EXTENSION IF NOT EXISTS orioledb' \
		-c \"SELECT extname, extversion FROM pg_extension WHERE extname = 'orioledb'\" \
		-c 'CREATE TABLE pgfuzz_smoke (i int NOT NULL, t text, PRIMARY KEY (i)) USING orioledb' \
		-c \"INSERT INTO pgfuzz_smoke SELECT g, 'row ' || g FROM generate_series(1, 100) g\" \
		-c 'SELECT count(*) FROM pgfuzz_smoke' \
		-c 'DROP TABLE pgfuzz_smoke'"

	as_fuzzuser "$PGBIN/pg_ctl -D temp/data -w stop"
fi

# ---------------------------------------------------------------------------
# Workspace-configured extensions, from PGFUZZ_EXTENSIONS.
#
# Deliberately generic: nothing here knows about any particular fork. A
# workspace evaluating a patch that ships contrib modules puts
# `extensions=mchar fulleq` in its workspace.conf and gets them created in the
# database the harnesses attach to; every other workspace is unaffected because
# the variable is empty and this whole block is skipped.
#
# It matters because a corpus full of SQL using a type is worthless if the type
# does not exist -- analysis fails with "type ... does not exist" and the
# statement never reaches any of the code under test.
#
# The orioledb flavor above has already started and stopped a server for its
# own CREATE EXTENSION, so this only runs when that did not.
# ---------------------------------------------------------------------------

# Out-of-tree plugins, exported by pgfuzz into plugins/<name>.
#
# Deliberately generic: the build system is DETECTED, not hardcoded per plugin,
# so an extension nobody has tried before works without touching this file.
# Three shapes cover essentially everything on PGXS:
#
#   CMakeLists.txt  -> cmake (timescaledb)
#   configure(.ac)  -> autogen/configure then make (postgis)
#   Makefile        -> plain PGXS (the large majority)
#
# A plugin that was ASKED FOR and does not build is a BUILD FAILURE.
#
# The tempting alternative -- warn and carry on so one broken extension does not
# cost the other twenty -- is how you end up fuzzing for eleven hours against a
# database that never contained the thing you wanted to test, and reporting
# coverage for it. The same rule already governs contrib extensions here, for
# the same reason. If a plugin should not be built, take it out of `plugins=`;
# that is a decision, and it leaves a trace in the workspace config.
# GCC_VERSION=0 on every plugin make.
#
# A plugin Makefile that probes `gcc -dumpversion` and then adds a gcc-only flag
# breaks a clang build, and these images have gcc installed even though nothing
# uses it. pgauditlogtofile does exactly that:
#
#     GCC_VERSION := $(shell gcc -dumpversion | cut -f1 -d.)
#     ifeq ($(shell [ $(GCC_VERSION) -ge 10 ] && echo true),true)
#     PG_CFLAGS += -fanalyzer
#
# and clang rejects -fanalyzer outright. Setting GCC_VERSION=0 makes the
# Makefile's own test fail, which is narrower than filtering flags out of
# PG_CFLAGS and does nothing at all to a plugin that never reads the variable.
PLUGIN_MAKE_VARS="GCC_VERSION=0"

# Strip -Werror from plugin Makefiles, and say so.
#
# A plugin's -Werror is its authors' development policy, not ours, and it is
# hostile to a compiler they did not test against. pg_cron sets it and clang
# then fails on PostgreSQL's OWN headers:
#
#     elog.h:192: error: 'format' attribute argument not supported: gnu_printf
#                        [-Werror,-Wignored-attributes]
#
# Nothing there is a defect in pg_cron or in PostgreSQL. We build these plugins,
# we do not develop them, and a warning we will not act on must not fail the
# build. Code generation is unaffected, so sanitizer coverage is unchanged.
#
# TWO FLAG TRICKS WERE TRIED FIRST AND BOTH WERE WRONG, which is why this edits
# the file instead:
#
#   COPT="-Wno-error"      lands in CFLAGS, and the compile line is
#                          `$(CC) $(CFLAGS) $(CPPFLAGS)`. The plugin's -Werror
#                          is in PG_CPPFLAGS, so it came LAST and won. The build
#                          looked fixed and failed identically.
#   CPPFLAGS="-Wno-error"  REPLACED the plugin's PG_CPPFLAGS rather than
#                          appending, taking -std=gnu11 and -Iinclude with it.
#                          -Werror went away and `struct timespec`,
#                          `sigjmp_buf` and `CLOCK_REALTIME` became unknown.
#
# Removing the flag is unambiguous and its effect is visible in the log.
strip_werror() {            # $1 = plugin directory
	local mf
	for mf in "$1"/Makefile "$1"/GNUmakefile; do
		[ -f "$mf" ] || continue
		grep -q -- '-Werror' "$mf" || continue
		sed -i 's/-Werror\b//g' "$mf"
		echo "build.sh: stripped -Werror from $(basename "$1")/$(basename "$mf")"
	done
}

build_plugins() {
	local pdir=$SRC/postgres/plugins
	[ -d "$pdir" ] || return 0
	local pgconfig=$1 destdir=$2 built="" failed=""

	local mf=$pdir/MANIFEST.tsv
	[ -f "$mf" ] || return 0

	# Install THIS workspace's plugin build dependencies.
	#
	# Not baked into the image, because the union of all plugins' dependencies
	# does not resolve: libgdal-dev (PostGIS) and libmariadb-dev (mysql_fdw)
	# conflict on this base. Installing only what the requested plugins need
	# means a workspace fails only if the plugins IT asked for are genuinely
	# incompatible -- and then the apt error names them, which is the useful
	# failure.
	if [ -s "$pdir/APT-DEPS" ]; then
		local deps; deps=$(tr '\n' ' ' < "$pdir/APT-DEPS" | xargs || true)
		if [ -n "$deps" ]; then
			echo "build.sh: plugin build deps: $deps"
			apt-get update -qq >/dev/null 2>&1 || true
			apt-get install -y --no-install-recommends $deps || {
				echo "ERROR: could not install plugin build dependencies: $deps" >&2
				echo "       If two plugins need conflicting libraries they cannot" >&2
				echo "       share a workspace; split them into two." >&2
				exit 1
			}
		fi
	fi

	while IFS=$'\t' read -r name sha apt preload create; do
		[ -n "${name:-}" ] || continue
		local d=$pdir/$name
		[ -d "$d" ] || { failed="$failed $name(missing)"; continue; }
		echo "build.sh: plugin $name ($sha) -- detecting build system"

		# Output goes to a log, never to /dev/null. Discarding it hid the reason
		# these installs put nothing in tmp_install, and cost a whole build
		# cycle to work out; the tail is printed on failure so the cause is in
		# the build log where someone will actually see it.
		local plog=/tmp/plugin-$name.log
		local ok=1

		# NO DESTDIR HERE -- deliberately, and not by oversight.
		#
		# pg_config is relocatable: make_relative_path() in src/port/path.c makes
		# it report paths relative to its OWN location whenever it has been moved
		# away from the prefix it was configured with. The pg_config we hand to
		# PGXS lives in tmp_install/usr/local/pgsql/bin, so it already reports
		# tmp_install/usr/local/pgsql/lib -- the destination we want.
		#
		# Passing DESTDIR on top of that prepends tmp_install a second time, and
		# `make install` cheerfully succeeds into
		#     bld/tmp_install/src/postgres/bld/tmp_install/usr/local/pgsql/lib
		# leaving nothing where anything looks for it. That cost a build cycle:
		# every plugin reported "built and installed" and then every CREATE
		# EXTENSION failed, because a zero exit from install says the copy
		# happened, not that it happened anywhere useful.
		#
		# Contrib (see the DESTDIR use further down) is the opposite case and is
		# correct as written: in-tree Makefiles resolve against Makefile.global's
		# configure-time prefix, which is NOT relocated, so there DESTDIR is what
		# redirects the install into tmp_install.
		if [ -f "$d/CMakeLists.txt" ]; then
			echo "build.sh:   cmake"
			( cd "$d" && { ./bootstrap -DPG_CONFIG="$pgconfig" \
			                 || cmake -S . -B build -DPG_CONFIG="$pgconfig"; } \
			   && make -C build -j"$(nproc)" \
			   && make -C build install ) > "$plog" 2>&1 || ok=0
		elif [ -f "$d/configure" ] || [ -f "$d/autogen.sh" ]; then
			echo "build.sh:   configure"
			( cd "$d" && { [ -f ./configure ] || ./autogen.sh; } \
			   && ./configure --with-pgconfig="$pgconfig" \
			   && make -j"$(nproc)" \
			   && make install ) > "$plog" 2>&1 || ok=0
		else
			echo "build.sh:   PGXS"
			strip_werror "$d"
			( make -C "$d" USE_PGXS=1 PG_CONFIG="$pgconfig" $PLUGIN_MAKE_VARS -j"$(nproc)" \
			   && make -C "$d" USE_PGXS=1 PG_CONFIG="$pgconfig" $PLUGIN_MAKE_VARS install \
			) > "$plog" 2>&1 || ok=0
		fi

		# "make install returned 0" is not the same as "the files are there":
		# a PGXS install can succeed against paths that are not where this build
		# looks. Assert the artifacts landed, and say where they went if not.
		if [ "$ok" = 1 ]; then
			local libdir="$destdir/usr/local/pgsql/lib"
			local extdir="$destdir/usr/local/pgsql/share/extension"
			# Check the name the extension INSTALLS UNDER, not the name of
			# the directory it was cloned into. They differ: pgsql-http
			# installs http.so and http.control, which is exactly why the
			# registry carries a `create` column. Checking only $name rejected
			# a plugin that had built and installed perfectly.
			if ! ls "$libdir/$name"*.so >/dev/null 2>&1 && \
			   ! ls "$extdir/$name"*.control >/dev/null 2>&1 && \
			   { [ -z "$create" ] || [ "$create" = "-" ] || \
			     { ! ls "$libdir/$create"*.so >/dev/null 2>&1 && \
			       ! ls "$extdir/$create"*.control >/dev/null 2>&1; }; }; then
				ok=0
				echo "ERROR: plugin $name: make install exited 0 but installed nothing under $destdir" >&2
				# Say where it DID go. The usual cause is a prefix applied twice
				# (see the DESTDIR note above), and the stray copy is the proof.
				local stray
				stray=$(find "$destdir" \( -name "$name*.so" -o -name "$name*.control" \) \
					-printf '%h\n' 2>/dev/null | sort -u | head -3)
				if [ -n "$stray" ]; then
					echo "       but these turned up elsewhere under $destdir:" >&2
					printf '%s\n' "$stray" | sed 's/^/         /' >&2
					echo "       -- a doubled prefix; check DESTDIR against pg_config's own paths." >&2
				else
					echo "       and nowhere under $destdir at all. install lines from $plog:" >&2
					grep -aiE '/usr/bin/install|^mkdir' "$plog" | tail -5 | sed 's/^/         /' >&2
				fi
			fi
		fi

		if [ "$ok" = 1 ]; then
			built="$built $name"
			echo "build.sh:   $name built and installed"
		else
			failed="$failed $name"
			echo "ERROR: plugin $name failed to build (tail of $plog):" >&2
			tail -15 "$plog" 2>/dev/null | sed 's/^/    /' >&2
		fi
	done < "$mf"

	{
		echo "built:${built:- none}"
		echo "failed:${failed:- none}"
	} > "$OUT/plugins.loaded"
	echo "build.sh: plugins built:${built:- none}${failed:+  FAILED:$failed}"

	if [ -n "$failed" ]; then
		echo "ERROR: these plugins were requested but did not build:$failed" >&2
		echo "       Fix the build, or remove them from plugins= in workspace.conf." >&2
		echo "       (Build output above; rerun with the make output unsuppressed to see why.)" >&2
		exit 1
	fi
}

# Plugins alone are enough to need this block: a workspace can fuzz out-of-tree
# extensions without configuring a single in-tree contrib one.
PLUGIN_MANIFEST=$SRC/postgres/plugins/MANIFEST.tsv
if { [ -n "${PGFUZZ_EXTENSIONS:-}" ] || [ -f "$PLUGIN_MANIFEST" ]; } && [ "$ORIOLEDB" != 1 ]; then
	echo "build.sh: creating extensions: ${PGFUZZ_EXTENSIONS:-none}"
	[ -f "$PLUGIN_MANIFEST" ] && \
		echo "build.sh: plugins: $(cut -f1 "$PLUGIN_MANIFEST" | tr '\n' ' ')"
	# Build and install the contrib modules FIRST, before the server is
	# configured or started.
	#
	# Ordering, not tidiness: a module named in `preload=` goes into
	# shared_preload_libraries below, and the postmaster resolves those at
	# startup. With the build happening afterwards the library did not exist
	# yet, so pg_ctl failed with "could not start server" and an *empty*
	# temp/ext.log -- the postmaster dies before logging is up, so the one
	# diagnostic that would name the missing library is the one that cannot be
	# written.
	# Build and install the contrib module each extension comes from. `make
	# createdb` runs temp-install, which installs core PostgreSQL only -- so
	# without this CREATE EXTENSION fails with "extension is not available",
	# which is what the first attempt at this did.
	#
	# Keyed on the extension name matching a contrib directory, which is the
	# usual convention; an extension that lives elsewhere just needs its module
	# built by other means before this runs.
	TOPBUILD=$PWD/../../..
	# ${...:-} because a workspace may configure plugins and no contrib
	# extensions at all; under set -u the bare name aborts the build.
	for ext in ${PGFUZZ_EXTENSIONS:-}; do
		if [ -d "$TOPBUILD/../contrib/$ext" ] || [ -d "$TOPBUILD/contrib/$ext" ]; then
			echo "build.sh: building contrib/$ext"
			su fuzzuser -c "make -C $TOPBUILD/contrib/$ext -j$(nproc)" \
				|| { echo "ERROR: building contrib/$ext failed" >&2; exit 1; }
			su fuzzuser -c "make -C $TOPBUILD/contrib/$ext DESTDIR=$TOPBUILD/tmp_install install" \
				|| { echo "ERROR: installing contrib/$ext failed" >&2; exit 1; }
		else
			echo "build.sh: no contrib/$ext directory; assuming $ext is already installed" >&2
		fi
	done

	# Out-of-tree plugins, built the same way and installed into the same
	# tmp_install, so everything downstream -- dynamic_library_path, the
	# instrumented rebuild, extension_funcs_fuzzer -- treats them identically.
	build_plugins "$TOPBUILD/tmp_install/usr/local/pgsql/bin/pg_config" \
		"$TOPBUILD/tmp_install"

	# Plugins that declare preload=yes are merged into PGFUZZ_PRELOAD here
	# rather than in the workspace config: whether a library needs preloading is
	# a property of the plugin, not a choice the workspace should have to know.
	if [ -f "$SRC/postgres/plugins/PRELOAD" ]; then
		PLUGIN_PRELOAD=$(tr '\n' ' ' < "$SRC/postgres/plugins/PRELOAD")
		# only those that actually built -- preloading a missing .so kills the
		# postmaster before logging is up, which is silent and costly
		for p in $PLUGIN_PRELOAD; do
			if [ -f "$TOPBUILD/tmp_install/usr/local/pgsql/lib/$p.so" ]; then
				PGFUZZ_PRELOAD="${PGFUZZ_PRELOAD:-} $p"
			else
				echo "build.sh: $p wants preloading but its .so is absent; skipping" >&2
			fi
		done
		PGFUZZ_PRELOAD=$(echo "${PGFUZZ_PRELOAD:-}" | xargs || true)
		[ -n "$PGFUZZ_PRELOAD" ] && echo "build.sh: preload after plugins: $PGFUZZ_PRELOAD"
	fi

	{
		# $libdir is compiled in as the configure prefix, /usr/local/pgsql/lib,
		# which exists in the build container but NOT in base-runner, where the
		# tree is mounted at /out/tmp_install. Without this, an extension's
		# library cannot be dlopen'd at fuzz time: the type resolves in the
		# catalog and then fmgr_info() fails loading its input function.
		#
		# This was previously written only in the orioledb branch, so a
		# workspace using the generic `extensions=` knob got its extensions
		# created at build time and then could not load them at run time --
		# mchar and mvarchar both failed to resolve, and before the resolution
		# was made non-fatal it killed the target silently.
		echo "dynamic_library_path = '\$libdir:/out/tmp_install/usr/local/pgsql/lib'"
		echo "listen_addresses = ''"
		echo "unix_socket_directories = '/tmp'"
		# Extensions that will not load any other way: they take shared memory,
		# register background workers, or install hooks, all of which happen in
		# _PG_init() under process_shared_preload_libraries_in_progress and are
		# an ERROR at CREATE EXTENSION time otherwise.  This data directory is
		# the one that becomes $OUT/data, and fuzzer_initialize.c calls
		# process_shared_preload_libraries(), so setting it here covers both
		# CREATE EXTENSION at build time and the backend at fuzz time.
		# Per-workspace settings, semicolon-separated, appended last so they can
		# override anything above. Some extensions cannot be CREATEd at all
		# without one -- pg_cron refuses unless cron.database_name names the
		# database it is being created in, and the alternative was dropping a
		# plugin that builds and loads perfectly well.
		if [ -n "${PGFUZZ_GUCS:-}" ]; then
			echo "build.sh: extra gucs: $PGFUZZ_GUCS" >&2
			printf '%s\n' "$PGFUZZ_GUCS" | tr ';' '\n' | sed 's/^ *//; s/ *$//' \
				| grep -v '^$' || true
		fi
		if [ -n "${PGFUZZ_PRELOAD:-}" ]; then
			echo "build.sh: shared_preload_libraries = $PGFUZZ_PRELOAD" >&2
			echo "shared_preload_libraries = '$(echo $PGFUZZ_PRELOAD | tr ' ' ',')'"
		fi
	} >> temp/data/postgresql.conf
	chown -R fuzzuser temp

	# See the note in the orioledb branch: su is setuid, so the loader drops
	# LD_LIBRARY_PATH across the exec and it has to be set inside the shell.
	PGLIB=$PWD/../../../tmp_install/usr/local/pgsql/lib
	as_fuzzuser() { su fuzzuser -c "LD_LIBRARY_PATH=$PGLIB $*"; }

	# Check the preload libraries exist before asking the postmaster to load
	# them. A missing one kills the postmaster before logging is up, so the
	# failure arrives as "could not start server" plus an empty ext.log, and
	# the name of the library that was not there appears nowhere at all.
	for lib in ${PGFUZZ_PRELOAD:-}; do
		if [ ! -f "$PGLIB/$lib.so" ]; then
			echo "ERROR: preload=$lib but $PGLIB/$lib.so does not exist" >&2
			echo "       (is $lib in extensions= too, so it gets built?)" >&2
			exit 1
		fi
	done

	if ! as_fuzzuser "$PGBIN/pg_ctl -D temp/data -w -l temp/ext.log start"; then
		echo "=== server failed to start for CREATE EXTENSION; log follows ===" >&2
		cat temp/ext.log >&2 || true
		[ -s temp/ext.log ] || echo "(ext.log is empty: the postmaster died before logging started, \
which usually means a shared_preload_libraries entry could not be loaded)" >&2
		exit 1
	fi
	for ext in ${PGFUZZ_EXTENSIONS:-}; do
		# ON_ERROR_STOP: a requested extension that will not install is a build
		# failure, not something to discover from empty results a day later.
		as_fuzzuser "$PGBIN/psql -h /tmp -d dbfuzz -v ON_ERROR_STOP=1 \
			-c 'CREATE EXTENSION IF NOT EXISTS $ext'" \
			|| { echo "ERROR: CREATE EXTENSION $ext failed" >&2; exit 1; }
	done

	# Plugins: a requested one that will not install is a build failure, exactly
	# as for contrib above. It built, so it must load; if it does not, the
	# database does not contain what the workspace asked to fuzz, and every
	# number produced afterwards would be about something else.
	if [ -f "$PLUGIN_MANIFEST" ]; then
		created=""; skipped=""
		while IFS=$'\t' read -r pname psha papt ppre pcreate; do
			[ -n "${pname:-}" ] || continue
			[ "${pcreate:-}" = "-" ] && continue        # library-only, nothing to create
			pcreate=${pcreate:-$pname}
			# Capture the error instead of discarding it. Swallowing psql's
			# message here would leave "would not load" with no reason, which
			# is exactly the kind of silent failure this project keeps paying
			# for -- the message names the cause (missing preload, wrong PG
			# major, absent .control file) and costs nothing to print.
			if cre_err=$(as_fuzzuser "$PGBIN/psql -h /tmp -d dbfuzz -v ON_ERROR_STOP=1 \
				-c 'CREATE EXTENSION IF NOT EXISTS \"$pcreate\" CASCADE'" 2>&1); then
				created="$created $pcreate"
			else
				skipped="$skipped $pcreate"
				echo "build.sh: CREATE EXTENSION $pcreate failed:" >&2
				printf '%s\n' "$cre_err" | sed 's/^/    /' >&2
			fi
		done < "$PLUGIN_MANIFEST"
		{
			echo "created:${created:- none}"
			echo "not_created:${skipped:- none}"
		} >> "$OUT/plugins.loaded"
		echo "build.sh: plugins created:${created:- none}${skipped:+  NOT created:$skipped}"
		if [ -n "$skipped" ]; then
			echo "ERROR: these plugins built but would not load:$skipped" >&2
			echo "       A plugin that cannot be created is not being fuzzed, so the" >&2
			echo "       run would measure something other than what was asked for." >&2
			exit 1
		fi
	fi

	as_fuzzuser "$PGBIN/psql -h /tmp -d dbfuzz \
		-c \"SELECT extname, extversion FROM pg_extension ORDER BY extname\""
	as_fuzzuser "$PGBIN/pg_ctl -D temp/data -w stop"
fi

# Type names for backend_types_fuzzer to resolve at runtime, from
# PGFUZZ_EXTRA_TYPES. A file rather than a compile-time list so the same binary
# serves every workspace and the list can change without a rebuild; absent
# means the harness adds nothing.
if [ -n "${PGFUZZ_EXTRA_TYPES:-}" ]; then
	echo "build.sh: extra fuzzable types: $PGFUZZ_EXTRA_TYPES"
	printf '%s\n' $PGFUZZ_EXTRA_TYPES > $OUT/extra_types.txt
fi

# Extension names for extension_funcs_fuzzer, which asks the catalog (pg_depend
# deptype 'e') which functions each one owns and calls them through fmgr.
#
# Separate from extra_types.txt on purpose: an extension's *types* and its
# *functions* are reached by different targets. backend_types_fuzzer covers the
# input functions a type name resolves to, which for mchar turned out to be
# about a fifth of the extension; the operators and functions -- mchar_op.c,
# mchar_proc.c, all of fulleq -- were at zero until this target existed.
{
	[ -n "${PGFUZZ_EXTENSIONS:-}" ] && printf '%s\n' $PGFUZZ_EXTENSIONS
	# Plugins go in the same list: extension_funcs_fuzzer resolves functions by
	# extension name through pg_depend, and does not care whether the extension
	# came from contrib or from a third-party repository. This is the payoff of
	# the plugin mechanism -- an extension that installs gets its whole SQL
	# surface fuzzed with no per-plugin work.
	if [ -f "$SRC/postgres/plugins/MANIFEST.tsv" ]; then
		while IFS=$'\t' read -r pn psha papt ppre pcreate; do
			[ -n "${pn:-}" ] || continue
			[ "${pcreate:-}" = "-" ] && continue
			printf '%s\n' "${pcreate:-$pn}"
		done < "$SRC/postgres/plugins/MANIFEST.tsv"
	fi
} | sort -u > $OUT/extensions.txt
if [ -s "$OUT/extensions.txt" ]; then
	echo "build.sh: fuzzable extension functions from: $(tr '\n' ' ' < $OUT/extensions.txt)"
else
	rm -f "$OUT/extensions.txt"
fi

# Functions extension_funcs_fuzzer must not call directly.
#
# A deadline bounds a function that computes and returns. It cannot bound one
# holding an extension's own shared-memory lock: cancelling inside the locked
# region unwinds past the code that would release it, and the next caller waits
# on that lock forever in an uninterruptible LWLockAcquire. That was observed --
# the backend sat in futex_do_wait at 0% CPU after the deadline cancelled 38
# calls -- and no amount of tuning the timeout changes it. Such functions are
# reached through the SQL fuzzers instead, where the executor arms
# statement_timeout and PostgreSQL owns the cancellation.
#
# Entries accept a schema, an extension, or extension.schema (with '*' for all
# schemas of an extension), so exclusion works at either granularity. Schema is
# the useful default: excluding orafce entirely would cost 405 functions to
# avoid 25.
#
# Per-workspace via `skip_schemas=` in workspace.conf, because which extensions
# are loaded is the experiment variable and what must be skipped follows from
# it. Set it to a single space to skip nothing and reproduce the deadlock.
if [ -n "${PGFUZZ_SKIP_SCHEMAS+x}" ]; then
	printf '%s\n' ${PGFUZZ_SKIP_SCHEMAS:-} > $OUT/extension_skip.txt
	echo "build.sh: extension_funcs skip list: ${PGFUZZ_SKIP_SCHEMAS:-(none)}"
else
	echo "build.sh: extension_funcs skip list: harness default (dbms_alert dbms_pipe dbms_lock)"
fi

# Extensions deliberately NOT fuzzed, from the workspace's
# `disabled_extensions=`.
#
# This is shouted rather than left implicit because the failure mode is
# silence: a patch ships five extensions, the workspace enables three, and
# every report afterwards says "the patch's functions are covered" while two of
# them were never loaded.  Nothing in a coverage report shows the absence of
# code that was never compiled into the database.
#
# An empty knob prints nothing. A non-empty one prints a banner into the build
# log and leaves the list in $OUT next to extensions.txt, so the exclusion
# travels with the build instead of living only in someone's memory.
if [ -n "${PGFUZZ_DISABLED_EXTENSIONS:-}" ]; then
	echo "###############################################################" >&2
	echo "## EXTENSIONS DELIBERATELY NOT FUZZED IN THIS BUILD:" >&2
	for d in $PGFUZZ_DISABLED_EXTENSIONS; do
		echo "##   $d" >&2
	done
	echo "## Their SQL functions are NOT reachable by any target here." >&2
	echo "## Reason is recorded in the workspace's workspace.conf." >&2
	echo "###############################################################" >&2
	printf '%s\n' $PGFUZZ_DISABLED_EXTENSIONS > $OUT/extensions.disabled
fi

mv temp/data .
cp -r data $OUT/
cd ../../..
cp -r tmp_install $OUT/

# An extension built here may link shared libraries the *runner* image does not
# have. mchar.so links ICU, base-runner has no libicu, and the failure surfaces
# far downstream as `could not load library ".../mchar.so": libicuuc.so.74:
# cannot open shared object file` -- with dynamic_library_path already correct
# and the .so already present, which is what made it look like a path problem
# for three build cycles.
#
# Unconditional, and it has to stay that way: the fuzz targets now link ICU
# dynamically (see FUZZ_LIBS) so that they and any dlopen'd extension share one
# ICU instead of two. That makes these libraries a hard run-time dependency of
# every target, not just of workspaces that configure extensions -- so this can
# no longer be gated on PGFUZZ_EXTENSIONS, and a failure here is a build
# failure rather than something to shrug at.
#
# The targets find them through an $ORIGIN rpath pointing at this directory, so
# no environment is needed at run time.
echo "build.sh: shipping ICU shared libraries"
cp -a /usr/lib/x86_64-linux-gnu/libicu*.so.* \
	$OUT/tmp_install/usr/local/pgsql/lib/ \
	|| { echo "ERROR: could not ship ICU; every target would fail to start" >&2; exit 1; }

# $ORIGIN in a DT_RUNPATH applies only to the object carrying it and is NOT
# inherited by that object's own dependencies -- so libicuuc finding libicudata
# needs its own. Skip symlinks: patchelf rewrites the file it is given, which
# would turn libicuuc.so.74 into a modified regular copy of its target.
for so in $OUT/tmp_install/usr/local/pgsql/lib/libicu*.so.*; do
	[ -f "$so" ] || continue
	[ -L "$so" ] && continue
	patchelf --set-rpath '$ORIGIN' "$so" \
		|| echo "WARNING: patchelf failed on $so" >&2
done

make clean

../configure --enable-cassert
make -j$(nproc)

# Rebuild workspace extensions against the *instrumented* tree.
#
# The copy already in $OUT came from the uninstrumented gcc build that exists
# only to run initdb, so it carries no sanitizer and no coverage instrumentation
# whatsoever.  It loads and runs -- which is exactly why this went unnoticed for
# a whole campaign -- but it is invisible to every tool pointed at it.  A
# coverage report over a corpus that had spent its entire run inside mchar's
# input function reported contrib/mchar as 0/0 lines: not zero percent, but
# absent, with no percentage to have.  A sanitizer would be equally blind to a
# bug inside it, which is the more expensive half of the problem.
#
# This configure -- unlike the two for the server tree above -- deliberately
# does not clear CC/CFLAGS, so bld/ carries the OSS-Fuzz compiler and flags. A
# plain `make -C contrib/$ext` here therefore inherits them, and needs none of
# the PGXS COPT/CC gymnastics the orioledb block below does.
if { [ -n "${PGFUZZ_EXTENSIONS:-}" ] || [ -f "$SRC/postgres/plugins/MANIFEST.tsv" ]; } && [ "$ORIOLEDB" != 1 ]; then
	EXTLIB=$OUT/tmp_install/usr/local/pgsql/lib
	EXTSOS=""

	# Plugins must be rebuilt instrumented too, for exactly the reason contrib
	# is: the copy installed during the uninstrumented pass carries no
	# sanitizer, so a fuzz target that dlopens it measures nothing and cannot
	# detect a memory error inside it. Rebuilt here against the instrumented
	# tree, with the uninstrumented copy kept as .plain for the real-postmaster
	# paths.
	if [ -f "$SRC/postgres/plugins/MANIFEST.tsv" ]; then
		PLUGDIR=$SRC/postgres/plugins
		while IFS=$'\t' read -r pn psha papt ppre pcreate; do
			[ -n "${pn:-}" ] || continue
			[ -d "$PLUGDIR/$pn" ] || continue
			echo "build.sh: rebuilding plugin $pn instrumented"
			PGC=$OUT/tmp_install/usr/local/pgsql/bin/pg_config
			if [ -f "$PLUGDIR/$pn/CMakeLists.txt" ] || [ -f "$PLUGDIR/$pn/configure" ]; then
				echo "build.sh:   $pn uses cmake/configure -- reusing the first-pass build" >&2
				echo "WARNING: $pn may be UNINSTRUMENTED; a crash inside it will not be caught" >&2
			else
				# Two separate things are required here, and each alone is a
				# no-op. Both were learned the hard way, one build apiece.
				#
				# `clean` FIRST, and not as tidiness: the first (uninstrumented)
				# pass built this same directory in place, so its .o and .so are
				# newer than the sources and make says "Nothing to be done for
				# 'all'". Contrib does not need this because `make clean` in
				# bld/ already reached it; plugins live outside the build tree.
				#
				# CC/CXX/COPT SECOND, and this is the part cleaning alone does
				# not fix. PGXS reads CFLAGS and CC from the *installed* tree's
				# Makefile.global and ignores the environment -- and the tree in
				# $OUT is a copy of the uninstrumented first pass, so it records
				# plain gcc with no sanitizer. Sanitizer flags therefore have to
				# enter through COPT, which Makefile.global appends to both
				# CFLAGS and LDFLAGS, and the compiler has to be overridden
				# outright, since gcc rejects clang's flags outright
				# (-fsanitize=fuzzer-no-link, -gline-tables-only).
				#
				# Unlike contrib, which builds inside bld/ and simply inherits
				# the instrumented Makefile.global, a plugin gets nothing for
				# free. This is the same gymnastics the orioledb block does, for
				# exactly the same reason.
				strip_werror "$PLUGDIR/$pn"
				make -C "$PLUGDIR/$pn" USE_PGXS=1 PG_CONFIG="$PGC" $PLUGIN_MAKE_VARS clean >/dev/null 2>&1 || true
				make -C "$PLUGDIR/$pn" USE_PGXS=1 PG_CONFIG="$PGC" $PLUGIN_MAKE_VARS -j"$(nproc)" \
					CC="$CC" CXX="$CXX" COPT="$CFLAGS" \
					|| { echo "ERROR: instrumented rebuild of plugin $pn failed" >&2; exit 1; }
			fi
			for so in "$PLUGDIR/$pn"/*.so; do
				[ -f "$so" ] || continue
				b=$(basename "$so")
				[ -f "$EXTLIB/$b" ] && cp -a "$EXTLIB/$b" "$EXTLIB/$b.plain"
				cp "$so" "$EXTLIB/$b"
				EXTSOS="$EXTSOS $EXTLIB/$b"
				# FATAL, not a warning. This fired correctly on the first
				# plugins build and changed nothing, because a warning in the
				# middle of a 6000-line build log is indistinguishable from
				# silence -- the build was declared good and shipped three
				# plugins that ASan could not see into. An uninstrumented plugin
				# is worse than an absent one: the campaign reports coverage and
				# finds nothing, and looks healthy doing it. A workspace that
				# asked for a plugin gets an instrumented plugin or an error.
				if ! nm "$EXTLIB/$b" 2>/dev/null | grep -q '__llvm_prf\|__asan_\|__sanitizer_cov'; then
					echo "ERROR: plugin $b carries no instrumentation -- the rebuild did not take." >&2
					echo "       It would load and run while being invisible to the sanitizer" >&2
					echo "       and contributing no coverage. Refusing to ship it." >&2
					exit 1
				fi
			done
		done < "$PLUGDIR/MANIFEST.tsv"
	fi

	for ext in ${PGFUZZ_EXTENSIONS:-}; do
		[ -d "contrib/$ext" ] || continue
		echo "build.sh: rebuilding contrib/$ext instrumented"
		make -C "contrib/$ext" -j$(nproc) \
			|| { echo "ERROR: instrumented rebuild of contrib/$ext failed" >&2; exit 1; }
		for so in contrib/$ext/*.so; do
			[ -f "$so" ] || continue
			b=$(basename "$so")
			# Keep the uninstrumented copy beside it, as the orioledb block
			# does and for the same reason: storage_fuzzer.py starts a real
			# postmaster out of tmp_install, whose binaries are gcc-built with
			# no sanitizer, and dlopening an instrumented library into those
			# fails on undefined __asan_* symbols.
			[ -f "$EXTLIB/$b" ] && cp -a "$EXTLIB/$b" "$EXTLIB/$b.plain"
			cp "$so" "$EXTLIB/$b"
			EXTSOS="$EXTSOS $EXTLIB/$b"
			# Never let this fail silently again -- a silent no-op here is
			# precisely what produced a coverage report that looked fine and
			# measured nothing. A warning was not enough: the same check on the
			# plugin path fired, was scrolled past, and the build shipped
			# anyway. Fail the build instead.
			if ! nm "$EXTLIB/$b" 2>/dev/null | grep -q '__llvm_prf\|__asan_\|__sanitizer_cov'; then
				echo "ERROR: $b carries no instrumentation -- the rebuild did not take." >&2
				echo "       Coverage over it would read 0/0 and a bug inside it" >&2
				echo "       would go undetected. Refusing to ship it." >&2
				exit 1
			fi
		done
	done

	# base-runner has no libicu, so copies are shipped beside the extension
	# (see above).  The loader still has to find them: dlopen resolves an
	# extension's DT_NEEDED entries through the normal search path, which does
	# not include this directory.  cmd_run sets LD_LIBRARY_PATH for that, but
	# `helper.py coverage` has no way to pass environment into the container at
	# all -- so the coverage run loaded no extension whatsoever and reported on
	# a database in which mchar did not exist.  An $ORIGIN RUNPATH makes the
	# library resolve its own dependencies wherever the tree happens to be
	# mounted, under every command, with no environment at all.
	# The ICU libraries need it too, and this is the part that is easy to get
	# wrong: DT_RUNPATH -- which is what modern linkers and patchelf emit --
	# applies *only* to the object that carries it, and is NOT inherited by
	# that object's own dependencies, the way the obsolete DT_RPATH was.  So
	# an $ORIGIN on mchar.so alone finds libicuuc and libicui18n and then
	# stops: libicuuc's dependency on libicudata is resolved using libicuuc's
	# runpath, which is empty, and the load fails on libicudata.so.74 with
	# every file involved sitting in the same directory.
	#
	# Skip symlinks: patchelf rewrites the file it is given, which would
	# replace libicuuc.so.74 -> libicuuc.so.74.2 with a modified regular copy.
	# Patching the real files is enough, since the links point at them.
	for so in $EXTSOS "$EXTLIB"/libicu*.so.*; do
		[ -f "$so" ] || continue
		[ -L "$so" ] && continue
		patchelf --set-rpath '$ORIGIN' "$so" \
			|| echo "WARNING: patchelf failed on $so; dlopen will need LD_LIBRARY_PATH" >&2
	done
fi

if [ "$ORIOLEDB" = 1 ]; then
	# Rebuild the extension instrumented and replace the copy already in $OUT.
	# PGXS takes CFLAGS from the installed Makefile.global and ignores the
	# environment, so the sanitizer flags have to go in through COPT, which
	# Makefile.global appends to both CFLAGS and LDFLAGS.
	# Build against the installed tree in $OUT, not bld/tmp_install: the
	# `make clean` above removed the latter, and the former is the copy the
	# fuzz targets will actually load orioledb.so from at runtime.
	OUT_PGCONFIG=$OUT/tmp_install/usr/local/pgsql/bin/pg_config
	make -C ../orioledb clean USE_PGXS=1 PG_CONFIG=$OUT_PGCONFIG ORIOLEDB_PATCHSET_VERSION=$ORIOLEDB_PATCHSET || true
	# CC/CXX must be overridden too, not just COPT: PGXS inherits the compiler
	# from the installed Makefile.global, which recorded gcc from the
	# uninstrumented configure, and gcc rejects clang's sanitizer flags
	# (-fsanitize=fuzzer-no-link, -gline-tables-only).
	make -C ../orioledb -j$(nproc) USE_PGXS=1 PG_CONFIG=$OUT_PGCONFIG ORIOLEDB_PATCHSET_VERSION=$ORIOLEDB_PATCHSET \
		CC="$CC" CXX="$CXX" COPT="$CFLAGS"
	# Keep the uninstrumented build beside the instrumented one.  The fuzz targets
	# need the instrumented orioledb.so, but storage_fuzzer.py starts a *real*
	# postmaster from tmp_install, and those binaries are gcc-built without a
	# sanitizer: dlopening an ASan-instrumented library into them fails on
	# undefined __asan_* symbols, so preloading it makes the server refuse to
	# start.  storage_fuzzer.py swaps this copy in inside its own private tree.
	# Under PGFUZZ_SERVER_ASAN the server itself is sanitized, so the
	# sanitized orioledb.so is the one that matches it -- keeping a plain
	# copy would give storage_fuzzer.py a library that no longer agrees with
	# the binary loading it.
	if [ "${PGFUZZ_SERVER_ASAN:-0}" != 1 ]; then  # plain server -> plain .so
		cp $OUT/tmp_install/usr/local/pgsql/lib/orioledb.so \
		   $OUT/tmp_install/usr/local/pgsql/lib/orioledb.so.plain
	fi
	cp ../orioledb/orioledb.so $OUT/tmp_install/usr/local/pgsql/lib/orioledb.so
	# Fatal, like the contrib and plugin checks: shipping an uninstrumented
	# extension means the campaign measures nothing and reports success.
	#
	# Match ANY instrumentation, not `__asan_` specifically. An undefined
	# (UBSan) build contains no `__asan_` symbols by definition, so grepping for
	# them fails every non-ASan build -- which is exactly what happened when
	# this check was promoted from a warning: oriole16-und died on a build that
	# was perfectly good, and oriole17-und and oriole18-und were queued to
	# follow. The coverage build likewise carries `__llvm_prf` rather than
	# either. `__sanitizer_cov` is the one constant: libFuzzer adds sancov to
	# every sanitizer configuration, so its absence is the real signal that
	# instrumentation did not reach the compile.
	if ! nm -D $OUT/tmp_install/usr/local/pgsql/lib/orioledb.so \
		| grep -q '__asan_\|__sanitizer_cov\|__llvm_prf'; then
		echo "ERROR: orioledb.so carries no instrumentation -- COPT did not reach the compile." >&2
		echo "       Fuzzing it would detect nothing. Refusing to ship it." >&2
		exit 1
	fi
fi

# Manually remove main function from main.c and recompile it
cd ../
apply_patch $SRC/main.diff \
	'ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION' src/backend/main/main.c
cd bld
$CC -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -I./src/include -I./src/include/port -I../src/include -fPIC -c ../src/backend/main/main.c -o ./src/backend/main/main.o

# Package static library
cd src/backend
ar rcs libpostgres.a $(find . -name '*.o' | grep -v '^./fuzzer/')

cd fuzzer
make -j$(nproc) fuzzer
cp *_fuzzer $OUT/

# ---------------------------------------------------------------------------
# Fuzzing dictionaries.
#
# base-runner's run_fuzzer picks up $OUT/<target>.dict automatically, so
# shipping the files is all that is needed.
#
# This is the evidence-backed half of the saturation fix. Measured on the
# 2026-08-07 sweep: most targets stopped finding new edges within the first few
# thousand inputs and then executed tens of millions more for nothing --
# network_fuzzer's last new edge was at input 3,185 of 120,694,635, regex at
# 3,642 of 105,508,180, jsonb at 17,679 of 96,031,401. The corpus kept growing
# the whole time, which is why this went unnoticed: libFuzzer keeps inputs that
# hit new edge-count buckets, not only new edges, so corpus growth is not
# evidence of coverage growth.
#
# A structured format cannot be discovered by random mutation. Asking a fuzzer
# to invent the token SELECT one byte at a time is asking for 2^48 tries; the
# dictionary hands it over and lets the search spend itself on structure
# instead of spelling.
# ---------------------------------------------------------------------------
echo "build.sh: generating fuzzing dictionaries"

# SQL keywords, taken from the tree actually being built rather than a list
# maintained here -- kwlist.h is authoritative and version-correct.
# Absolute: at this point the cwd is bld/src/backend/fuzzer, and a relative
# path here silently missed the file for a whole build cycle -- the WARNING
# below is what caught it.
KW=$SRC/postgres/src/include/parser/kwlist.h
if [ -f "$KW" ]; then
	sed -n 's/^PG_KEYWORD("\([^"]*\)".*/"\1"/p' "$KW" > /tmp/sql.dict
	# Punctuation and operators the grammar needs and kwlist.h does not carry.
	# One token per line: libFuzzer's dictionary parser is strict, and it
	# rejects the WHOLE file on the first malformed line (it does not skip it),
	# which silently disables the dictionary. Multiple tokens on one line is
	# malformed.
	cat >> /tmp/sql.dict <<'DICTEOF'
"SELECT "
"FROM "
"WHERE "
"INSERT INTO "
"VALUES "
"UPDATE "
"DELETE FROM "
"CREATE TABLE "
"DROP TABLE "
"ALTER TABLE "
"CREATE INDEX "
"JOIN "
"ON "
"GROUP BY "
"ORDER BY "
"HAVING "
"LIMIT "
"OFFSET "
"UNION ALL "
"WITH "
"RETURNING "
"PARTITION BY "
"OVER "
"CASE WHEN "
"THEN "
"ELSE "
"END"
"::"
"->"
"->>"
"#>"
"#>>"
"||"
"!="
"<>"
">="
"<="
":="
".."
"$$"
"$1"
"("
")"
"["
"]"
","
";"
"'"
"\""
"*"
"%"
"_"
"NULL"
"TRUE"
"FALSE"
"DEFAULT"
"PRIMARY KEY"
"FOREIGN KEY"
"REFERENCES"
"generate_series"
"pg_catalog"
"information_schema"
"public."
DICTEOF
	for t in simple_query_fuzzer spi_query_fuzzer raw_parser_fuzzer; do
		[ -f "$OUT/$t" ] && cp /tmp/sql.dict "$OUT/$t.dict"
	done
	echo "build.sh:   sql.dict: $(wc -l < /tmp/sql.dict) entries"
else
	echo "WARNING: $KW not found; SQL targets get no dictionary" >&2
fi

# The rest are small and hand-written: the tokens each format is made of.
mk_dict() {
	local target=$1; shift
	[ -f "$OUT/$target" ] || return 0
	printf '%s\n' "$@" > "$OUT/$target.dict"
}

mk_dict json_parser_fuzzer '"{"' '"}"' '"["' '"]"' '":"' '","' '"true"' '"false"' \
	'"null"' '"\\u"' '"\\n"' '"\\\""' '"0"' '"-0"' '"1e309"' '"1E-309"' '"\"\""'
cp "$OUT/json_parser_fuzzer.dict" "$OUT/jsonb_fuzzer.dict" 2>/dev/null || true

mk_dict jsonpath_fuzzer '"$"' '"$."' '"$[*]"' '"@"' '"?("' '")"' '"&&"' '"||"' \
	'"=="' '"!="' '">="' '"<="' '"like_regex"' '"starts with"' '"exists"' \
	'".type()"' '".size()"' '".double()"' '".ceiling()"' '".keyvalue()"' '"strict "' '"lax "'

mk_dict datetime_fuzzer '"infinity"' '"-infinity"' '"now"' '"today"' '"epoch"' \
	'"BC"' '"AD"' '"AM"' '"PM"' '"UTC"' '"GMT"' '"EST5EDT"' '"PST8PDT"' \
	'"January"' '"Jan"' '"Mon"' '"1970-01-01"' '"24:00:00"' '"+00:00"' '"-12:59"' \
	'"years"' '"months"' '"days"' '"hours"' '"ago"' '"P1Y2M3DT4H5M6S"' '"allballs"'

mk_dict hba_file_fuzzer '"local"' '"host"' '"hostssl"' '"hostnossl"' '"hostgssenc"' \
	'"all"' '"replication"' '"trust"' '"reject"' '"scram-sha-256"' '"md5"' '"peer"' \
	'"ident"' '"ldap"' '"cert"' '"samehost"' '"samenet"' '"0.0.0.0/0"' '"::1/128"' \
	'"include"' '"include_if_exists"' '"@"' '"\"\""'

mk_dict config_file_fuzzer '"shared_buffers"' '"work_mem"' '"max_connections"' \
	'"log_statement"' '"search_path"' '"timezone"' '"include"' '"include_dir"' \
	'"include_if_exists"' '"on"' '"off"' '"= "' '"MB"' '"GB"' '"kB"' '"ms"' '"min"' \
	'"#"' '"'"'"'"' '"\"\""' '"\\"'

mk_dict numeric_fuzzer '"NaN"' '"Infinity"' '"-Infinity"' '"1e-1000"' '"1e1000"' \
	'"0.0"' '"-0"' '"1_000"' '"0x1p3"' '"."' '"e"' '"E+"' '"1e"'

mk_dict regex_fuzzer '"(?:"' '"(?="' '"(?!"' '"(?<="' '"[[:alpha:]]"' '"[^"' '"\\b"' \
	'"\\d"' '"\\w"' '"{0,255}"' '"*?"' '"+?"' '"|"' '"^"' '"$"' '"(*)"' '"\\1"'

mk_dict network_fuzzer '"0.0.0.0"' '"255.255.255.255"' '"::"' '"::1"' '"/0"' '"/32"' \
	'"/128"' '"fe80::"' '"::ffff:"' '"08:00:2b:01:02:03"' '"%eth0"'

mk_dict geo_fuzzer '"("' '")"' '"<"' '">"' '"["' '"]"' '","' '"NaN"' '"Infinity"' '"0,0"'

mk_dict tsearch_fuzzer '"&"' '"|"' '"!"' '"<->"' '"<2>"' '":*"' '":A"' '":AB"' \
	'"simple"' '"english"' '"'"'"'"' '"("' '")"'

mk_dict formatting_fuzzer '"YYYY"' '"MM"' '"DD"' '"HH24"' '"MI"' '"SS"' '"MS"' \
	'"US"' '"TZ"' '"Month"' '"Day"' '"FM"' '"TH"' '"999"' '"0999"' '"9G999"' \
	'"L"' '"D"' '"S"' '"PR"' '"RN"' '"EEEE"' '"FX"' '"TM"' '"Q"' '"WW"' '"IW"' \
	'"J"' '"CC"' '"B"' '"V"' '"."' '","'

mk_dict scalar_types_fuzzer '"true"' '"false"' '"NULL"' '"NaN"' '"Infinity"' \
	'"-Infinity"' '"1e308"' '"-1e308"' '"0x7fffffff"' '"-2147483648"' \
	'"9223372036854775807"' '"\\x"' '"{}"' '"{1,2}"' '"1970-01-01"'

mk_dict encoding_fuzzer '"UTF8"' '"LATIN1"' '"WIN1251"' '"EUC_JP"' '"SJIS"' '"BIG5"' \
	'"GB18030"' '"SQL_ASCII"' '"\\xc3\\xa9"' '"\\xef\\xbb\\xbf"' '"\\xed\\xa0\\x80"'

echo "build.sh:   dictionaries: $(ls $OUT/*.dict 2>/dev/null | wc -l) targets"

# Emit a .options file with an ABSOLUTE dict path for every dictionary.
#
# base-runner's run_fuzzer passes the dict as a relative "-dict=<target>.dict"
# from $OUT. That is fine for the standalone parsers, but the backend targets
# (simple_query, spi_query, scalar_types) chdir into the PostgreSQL data
# directory during LLVMFuzzerInitialize, so by the time libFuzzer resolves the
# relative path the cwd is no longer $OUT -- it fails with "ParseDictionaryFile:
# file does not exist or is empty", libFuzzer exits 1, and the target executes
# ZERO inputs while the campaign still records a (dead) run. It cost the three
# most important query targets an entire campaign, invisibly.
#
# run_fuzzer reads "dict = ..." from <target>.options and passes it verbatim, so
# an absolute path there resolves regardless of cwd. Harmless for the standalone
# targets, which an absolute path suits equally well. $OUT is /out in the run
# container too, so this path is correct at fuzz time.
for d in "$OUT"/*.dict; do
	[ -f "$d" ] || continue
	t=$(basename "$d" .dict)
	printf '[libfuzzer]\ndict = %s/%s.dict\n' "$OUT" "$t" > "$OUT/$t.options"
done
echo "build.sh:   .options (absolute dict path): $(ls $OUT/*.options 2>/dev/null | wc -l) targets"
cd ../../..					# bld/src/backend/fuzzer -> bld

# conninfo_fuzzer is the one client-side target: it links libpq, not the
# backend, so it cannot be built by the backend Makefile (postgres.h and
# postgres_fe.h are mutually exclusive).  --start-group because libpq,
# libpgcommon and libpgport reference each other both ways.
# CPPFLAGS is not part of the OSS-Fuzz build environment, and build.sh runs
# under "set -u", so it must be defaulted rather than referenced bare.
$CC $CFLAGS ${CPPFLAGS:-} \
	-DFRONTEND \
	-I src/include -I ../src/include -I ../src/interfaces/libpq \
	-c ../src/backend/fuzzer/conninfo_fuzzer.c -o conninfo_fuzzer.o
# The *_shlib variants, not the plain ones: src/common/Makefile builds
# libpgcommon.a with the encoding entry points renamed to "*_private" (so a
# statically linked frontend cannot collide with a backend that dlopens it),
# while libpq.a references the unrenamed names.  Linking plain libpgcommon.a
# here fails with undefined references to pg_encoding_to_char and friends.
$CXX $CFLAGS conninfo_fuzzer.o \
	-Wl,--start-group \
		src/interfaces/libpq/libpq.a \
		src/common/libpgcommon_shlib.a \
		src/port/libpgport_shlib.a \
	-Wl,--end-group \
	$LIB_FUZZING_ENGINE -lm -lpthread -o conninfo_fuzzer
cp conninfo_fuzzer $OUT/

# Seed corpora.  The SQL statement corpus is useful to every target that takes
# a SQL string; the others start cold and are grown by the pgfuzz driver.
for t in simple_query_fuzzer raw_parser_fuzzer spi_query_fuzzer; do
	cp $SRC/simple_query_fuzzer_seed_corpus.zip $OUT/${t}_seed_corpus.zip
done

# Provenance, written into the build itself rather than left to whoever invokes
# it.  Artifacts produced from this build embed this verbatim, so a scenario
# JSON found months later says which source, which sanitizer and -- since there
# is now more than one -- which *build mode* produced it.  Getting this wrong is
# not hypothetical: replaying artifacts that predated a scenario field silently
# ran them under different settings and wasted a whole triage round.
# Plugin provenance, as name:sha pairs, embedded so one edition can be compared
# against another WITHOUT its source tree -- which is gone by the time anyone
# asks. A "local:<sha>" value means a patched working tree. Differing values
# between editions mean they are not testing the same software, which is how a
# coverage build spent two days measuring stock orafce while the fuzzing builds
# ran the patched one. See scripts/check-build-sync.sh.
PLUGIN_PROV=""
if [ -f "$SRC/postgres/plugins/MANIFEST.tsv" ]; then
	PLUGIN_PROV=$(awk -F'\t' 'NF>=2 && $1!="" {
		printf "%s\"%s\": \"%s\"", (n++ ? ", " : ""), $1, $2
	}' "$SRC/postgres/plugins/MANIFEST.tsv")
fi

cat > $OUT/BUILD-INFO.json <<EOF
{
  "pg_ref_sha": "${PGSHA:-unknown}",
  "plugins": {${PLUGIN_PROV}},
  "orioledb": $([ "$ORIOLEDB" = 1 ] && echo true || echo false),
  "sanitizer": "${SANITIZER:-unknown}",
  "fuzzing_engine": "${FUZZING_ENGINE:-unknown}",
  "server_tree": "$(if [ "${PGFUZZ_SERVER_ASAN:-0}" = 1 ]; then echo "sanitized, --disable-cassert"; elif [ "${PGFUZZ_SERVER_CASSERT:-1}" = 0 ]; then echo "uninstrumented gcc, --disable-cassert"; else echo "uninstrumented gcc, --enable-cassert"; fi)",
  "server_asan": $([ "${PGFUZZ_SERVER_ASAN:-0}" = 1 ] && echo true || echo false),
  "cassert": $([ "${PGFUZZ_SERVER_ASAN:-0}" = 1 ] || [ "${PGFUZZ_SERVER_CASSERT:-1}" = 0 ] && echo false || echo true),
  "built_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF

# Ownership is handed back by the EXIT trap installed at the top.

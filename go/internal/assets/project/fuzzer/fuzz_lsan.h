/*-------------------------------------------------------------------------
 *
 * fuzz_lsan.h
 *	  Stop LeakSanitizer judging one-time initialization by a per-input rule.
 *
 * LSan reports at process exit.  A fuzz target's one-time initialization
 * allocates memory that is *meant* to live until the process dies -- and
 * protocol_fuzzer's initialization runs PostgreSQL's own backend startup,
 * which strdup()s the database name in process_postgres_switches() and never
 * frees it, because a real backend exits rather than tidying up.
 *
 * libFuzzer turns the resulting report into a crash, writes an artifact named
 * after whatever input was loaded -- the EMPTY one, sha1
 * da39a3ee5e6b4b0d3255bfef95601890afd80709, which reproduces nothing -- and
 * kills the target.  Measured across the campaign: 244 such reports, every one
 * of them this single allocation:
 *
 *     Direct leak of 7 byte(s) in 1 object(s)
 *     DEDUP_TOKEN: __interceptor_strdup--process_postgres_switches--PostgresSingleUserMain
 *
 * Seven bytes, once per process, costing the target its entire run.
 *
 * WHY __lsan_disable AND NOT A SUPPRESSIONS FILE
 * ==============================================
 * __lsan_disable/__lsan_enable scope the exemption by TIME, which is the
 * actual predicate here: "allocated during one-time init".  A suppressions
 * file scopes by SYMBOL, which is a proxy, and a fragile one -- with the
 * default fast_unwind_on_malloc the frame a suppression must match is
 * frequently absent from the stack.  This project already hit exactly that:
 * FINDINGS/spi-tuptable-leak records that the default fast unwind "gives a
 * useless stack".  A suppression that silently fails to match is
 * indistinguishable from one that works.
 *
 * It also avoids an env-merging problem: OSS-Fuzz's run_fuzzer composes
 * ASAN_OPTIONS itself, so a suppressions path has to survive pgfuzz,
 * matrix.sh and triage-target.sh agreeing about it -- the same class of
 * failure as the detect_leaks=0 setting that was believed reverted and was
 * live for weeks.
 *
 * THE RISK, AND WHAT CATCHES IT
 * =============================
 * If a longjmp ever escaped past an __lsan_enable(), the disable counter would
 * stay nonzero and the target would run with leak detection OFF while looking
 * perfectly healthy -- the worst failure in this project's catalogue, since
 * every leak the campaign exists to find would be silently absent.
 *
 * That is precisely what scripts/probe-harness.sh --leak checks: a deliberate
 * 1234-byte leak that MUST be reported.  The probe predates this header and is
 * already green on all three targets; it must stay green after this change, and
 * that is the acceptance test.  protocol_fuzzer's siglongjmp target sits INSIDE
 * its own window, so the enable is still reached when __wrap_proc_exit unwinds
 * out of the backend.
 *
 * PGFUZZ_LSAN_INIT=1 disables the bracket at run time, so one build can still
 * answer "does initialization leak?" without being rebuilt -- which matters
 * when evaluating an extension, because _PG_init() and shmem_startup_hook()
 * run inside the window via process_shared_preload_libraries().
 *
 *-------------------------------------------------------------------------
 */
#ifndef PG_FUZZ_LSAN_H
#define PG_FUZZ_LSAN_H

#include <stdlib.h>

/*
 * Clang exposes __has_feature; GCC defines __SANITIZE_ADDRESS__.  An
 * unrecognised name inside __has_feature evaluates to 0, so naming
 * leak_sanitizer is harmless on compilers that do not know it.
 *
 * This guard is load-bearing rather than defensive: the -und (UBSan) and -cov
 * (coverage) workspaces link no LSan runtime, so an unguarded __lsan_disable()
 * would fail to link there and take out two thirds of the matrix for a fix
 * aimed at the other third.
 */
#if defined(__has_feature)
#if __has_feature(address_sanitizer) || __has_feature(leak_sanitizer)
#define PGFUZZ_HAVE_LSAN 1
#endif
#endif
#if !defined(PGFUZZ_HAVE_LSAN) && defined(__SANITIZE_ADDRESS__)
#define PGFUZZ_HAVE_LSAN 1
#endif

#ifdef PGFUZZ_HAVE_LSAN

#include <sanitizer/lsan_interface.h>

static inline int
pgfuzz_lsan_bracket_init(void)
{
	static int	cached = -1;

	if (cached < 0)
	{
		const char *v = getenv("PGFUZZ_LSAN_INIT");

		cached = (v != NULL && v[0] == '1') ? 0 : 1;
	}
	return cached;
}

#define PGFUZZ_LSAN_INIT_BEGIN() \
	do { if (pgfuzz_lsan_bracket_init()) __lsan_disable(); } while (0)
#define PGFUZZ_LSAN_INIT_END() \
	do { if (pgfuzz_lsan_bracket_init()) __lsan_enable(); } while (0)

#else							/* !PGFUZZ_HAVE_LSAN */

#define PGFUZZ_LSAN_INIT_BEGIN()	((void) 0)
#define PGFUZZ_LSAN_INIT_END()		((void) 0)

#endif							/* PGFUZZ_HAVE_LSAN */

#endif							/* PG_FUZZ_LSAN_H */

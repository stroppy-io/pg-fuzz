/*-------------------------------------------------------------------------
 *
 * fuzz_util.h
 *	  Shared scaffolding for the "standalone" PostgreSQL fuzz harnesses.
 *
 * A standalone harness links the backend code but never boots a backend: no
 * data directory, no shared memory, no catalog.  That makes it fast (tens of
 * thousands of executions per second) and reproducible, at the cost of only
 * being able to reach code that does not look anything up in the catalog.
 * Harnesses that need a real backend call FuzzerInitialize() instead -- see
 * spi_query_fuzzer.c.
 *
 * Two things every harness here needs:
 *
 *	1. Enough initialization that PostgreSQL's error handling works at all.
 *	   ereport(ERROR) siglongjmps to *PG_exception_stack, so if nothing has
 *	   installed one, the first malformed input aborts the process and the
 *	   fuzzer reports a "crash" that is really just a rejected input.
 *
 *	2. A memory context per iteration.  PostgreSQL's parsers palloc freely and
 *	   rely on the caller resetting a context afterwards; without that the
 *	   fuzzer would OOM after a few hundred thousand inputs and we would spend
 *	   a day triaging a leak that is not a leak.
 *
 * Portions Copyright (c) 1996-2024, PostgreSQL Global Development Group
 *
 *-------------------------------------------------------------------------
 */
#ifndef PG_FUZZ_UTIL_H
#define PG_FUZZ_UTIL_H

#include "postgres.h"

#include "fmgr.h"
#include "miscadmin.h"
#include "utils/guc.h"
#include "utils/memutils.h"
/* pg_initialize_timing(); present from PostgreSQL 19, harmless before it */
#include "portability/instr_time.h"

#include <setjmp.h>
#include <stdlib.h>
#include <string.h>

#include "fuzz_probe.h"
#include "fuzz_lsan.h"

/*
 * Body of one fuzz iteration.  "s" is a NUL-terminated copy of the input,
 * "len" is its length excluding the NUL (the input may contain embedded NULs;
 * cstring-based callees will simply stop at the first one).  "sel" is the
 * variant selector, see pgfuzz_select().
 */
typedef void (*pgfuzz_body) (const char *s, size_t len, int sel);

static bool pgfuzz_ready = false;

/*
 * One-time initialization.  Call from LLVMFuzzerInitialize().
 */
static inline void
pgfuzz_init(void)
{
	if (pgfuzz_ready)
		return;

	/*
	 * Inside the function, not around its call sites:
	 * json_parser_fuzzer calls pgfuzz_init() from LLVMFuzzerTestOneInput,
	 * so it initialises during iteration 1. Bracketing here covers that
	 * and still leaves the rest of the iteration fully judged.
	 */
	PGFUZZ_LSAN_INIT_BEGIN();

	/* TopMemoryContext, ErrorContext, and friends */
	MemoryContextInit();

	/*
	 * PostgreSQL 19 added a timing subsystem that InitializeGUCOptions()
	 * depends on: applying the compiled-in default for timing_clock_source
	 * runs check_timing_clock_source(), which does Assert(timing_initialized)
	 * on a non-EXEC_BACKEND build.  A real backend gets this from
	 * PostmasterMain() calling pg_initialize_timing() before GUC setup; we
	 * removed main() and do our own initialization, so nothing had called it
	 * and *every* target on 19 aborted inside LLVMFuzzerInitialize.  That is
	 * what made the pg19 workspaces look 26x cleaner than 17 when they were
	 * simply dead -- see FINDINGS/README.md.
	 *
	 * Guarded on the version because the function does not exist before 19.
	 */
#if PG_VERSION_NUM >= 190000
	pg_initialize_timing();
#endif

	/*
	 * Loads every GUC's compiled-in default -- DateStyle, IntervalStyle,
	 * standard_conforming_strings, lc_monetary, max_stack_depth -- and calls
	 * pg_timezone_initialize(), which gives us a GMT session_timezone without
	 * needing the timezone database on disk.  Several type input functions
	 * dereference session_timezone unconditionally, so skipping this would
	 * produce NULL-deref "crashes" that no real backend can hit.
	 */
	InitializeGUCOptions();

	/*
	 * set_stack_base() deliberately does NOT go here; it is called per
	 * iteration from pgfuzz_run().  Recording the base on this frame is what
	 * the first version did, and it silently disabled the recursion guard --
	 * see the note in pgfuzz_run().
	 */

	pgfuzz_ready = true;

	PGFUZZ_LSAN_INIT_END();
}

/*
 * Consume the leading byte of the input as a variant selector, so that a
 * single harness can cover a family of related entry points and let the
 * fuzzer decide how to split its budget between them.
 */
static inline int
pgfuzz_select(const uint8_t **data, size_t *size, int nvariants)
{
	int			sel = 0;

	if (*size > 0)
	{
		sel = (int) ((*data)[0] % (unsigned) nvariants);
		(*data)++;
		(*size)--;
	}
	return sel;
}

/*
 * Run one iteration of "body" with PostgreSQL's error handling installed and
 * a scratch memory context in place.
 *
 * An ereport(ERROR) out of body() is the normal case -- it means PostgreSQL
 * rejected the input, which is the correct behavior, not a finding.  We
 * swallow it and move on.  What we are hunting for is what ereport cannot
 * catch: sanitizer reports, assertion failures, hangs, and unbounded memory.
 */
static inline void
pgfuzz_run(pgfuzz_body body, const uint8_t *data, size_t size, int sel)
{
	MemoryContext ctx;
	MemoryContext oldctx;
	sigjmp_buf	jmpbuf;
	char	   *s;

	/* Prove leak detection is live on this target; see fuzz_probe.h. */
	pgfuzz_probe_leak_canary();

	/*
	 * Record the stack base on the frame the input actually runs on, so
	 * check_stack_depth() turns runaway recursion in the recursive-descent
	 * parsers into an ERROR rather than a segfault.
	 *
	 * This has to be per iteration, not once in pgfuzz_init().  libFuzzer
	 * calls LLVMFuzzerInitialize at a different call depth than it calls
	 * LLVMFuzzerTestOneInput, so a base recorded during initialization is
	 * offset from every input's stack by a constant -- and stack_is_too_deep()
	 * takes the *absolute value* of base minus current, so when the
	 * initialization frame is the deeper of the two that offset is handed to
	 * the guard as extra budget.  The guard then keeps returning false all the
	 * way down until the real stack runs out.
	 *
	 * It fails silently and in the permissive direction, which is the worst
	 * combination: `SELECT repeat('[', 80000)::json`, which stock PostgreSQL
	 * rejects cleanly with "stack depth limit exceeded", instead produced an
	 * ASan stack-overflow *inside check_stack_depth() itself* -- a crash
	 * report that looks exactly like a genuine PostgreSQL recursion bug and is
	 * entirely an artifact of this harness.  Every such report from these
	 * targets before this fix is a false positive, and every real recursion
	 * bug they might have found was equally invisible.
	 */
	set_stack_base();

	/*
	 * malloc rather than palloc: this buffer must outlive the per-iteration
	 * context reset that happens on the error path.
	 */
	s = (char *) malloc(size + 1);
	if (s == NULL)
		return;
	if (size > 0)
		memcpy(s, data, size);
	s[size] = '\0';

	ctx = AllocSetContextCreate(TopMemoryContext,
								"fuzz iteration",
								ALLOCSET_SMALL_SIZES);
	oldctx = MemoryContextSwitchTo(ctx);

	if (sigsetjmp(jmpbuf, 0) == 0)
	{
		PG_exception_stack = &jmpbuf;
		error_context_stack = NULL;

		body(s, size, sel);
	}
	else
	{
		/* input rejected by PostgreSQL; reset the error machinery */
		MemoryContextSwitchTo(ctx);
		FlushErrorState();
	}

	PG_exception_stack = NULL;
	error_context_stack = NULL;

	MemoryContextSwitchTo(oldctx);
	MemoryContextDelete(ctx);
	free(s);

	/*
	 * PGFUZZ_CTX_STATS=N: dump MemoryContextStats(TopMemoryContext) every N
	 * iterations.  Off unless the variable is set.
	 *
	 * This exists because the interesting failure is not the kind LSan finds.
	 * datetime_fuzzer grows RSS by a flat ~185 bytes per iteration -- 80MB to
	 * 2,532MB over 13.1M executions, dead linear -- and libFuzzer eventually
	 * kills it with an out-of-memory whose artifact is named after whichever
	 * input happened to be running.  Leak detection reports none of it, and
	 * correctly so: the memory is still *reachable* from a live memory
	 * context, which is not LSan's definition of a leak.  The context it is
	 * reachable from is the thing worth knowing, and this is the cheapest way
	 * to ask PostgreSQL directly rather than infer it from allocation traces.
	 */
	{
		static long stats_every = -1;
		static long iter = 0;

		if (stats_every < 0)
		{
			const char *v = getenv("PGFUZZ_CTX_STATS");

			stats_every = (v != NULL) ? atol(v) : 0;
		}

		iter++;
		if (stats_every > 0 && (iter % stats_every) == 0)
		{
			MemoryContext c;

			fprintf(stderr, "=== PGFUZZ_CTX_STATS after %ld iterations ===\n", iter);

			/*
			 * Walk the children explicitly instead of letting
			 * MemoryContextStats() recurse.
			 *
			 * MemoryContextStatsInternal() only descends into children when
			 * `level < max_level && !stack_is_too_deep()`, and summarizes them
			 * as "N more child contexts containing ..." otherwise.  In this
			 * harness it summarized all four children of TopMemoryContext,
			 * which is a single number and tells us nothing about which one is
			 * growing -- the whole question.
			 *
			 * Calling MemoryContextStats() per child sidesteps that: the
			 * "examine the context itself" step is unconditional, so each
			 * child prints its own line whatever the stack check decides.
			 */
			MemoryContextStats(TopMemoryContext);
			for (c = TopMemoryContext->firstchild; c != NULL; c = c->nextchild)
				MemoryContextStats(c);
			fflush(stderr);
		}
	}
}

/*
 * Call a type input function of the form foo_in(cstring) or
 * foo_in(cstring, oid typioparam, int4 typmod).  Getting the arity wrong
 * matters: a 3-argument input function reading PG_GETARG_INT32(2) out of a
 * 1-argument FunctionCallInfo reads uninitialized memory and manufactures
 * bugs that do not exist.
 */
static inline Datum
pgfuzz_call_in(PGFunction fn, bool three_args, const char *s, Oid typioparam)
{
	if (three_args)
		return DirectFunctionCall3(fn,
								   CStringGetDatum(s),
								   ObjectIdGetDatum(typioparam),
								   Int32GetDatum(-1));
	return DirectFunctionCall1(fn, CStringGetDatum(s));
}

#endif							/* PG_FUZZ_UTIL_H */

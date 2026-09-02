/*-------------------------------------------------------------------------
 *
 * fuzz_canary.h
 *	  Per-iteration resource-invariant checks for the backend harnesses.
 *
 * WHY THIS EXISTS
 * ===============
 * On 2026-08-15 spi_query_fuzzer was managing 77 executions per run against
 * 104,501 for a standalone target in the same sweep.  It looked like a starved
 * or broken target.  It was not: the target was finding a real leak, LeakSani-
 * tizer was killing the process on it, and the restart loop was the symptom.
 *
 * Two things about how that was found are worth never repeating:
 *
 *	1. LSan reports at process exit (or on libFuzzer's malloc/free imbalance
 *	   heuristic), and attributes the leak to whatever input happened to be
 *	   executing.  The corpus run blamed compute_index_stats; replaying the one
 *	   input in isolation showed the real site, ExecVacuum.  Attribution from a
 *	   corpus run is not evidence.
 *
 *	2. LSan only sees memory that is *unreachable*.  A PostgreSQL memory context
 *	   still linked under TopMemoryContext is perfectly reachable, so a context
 *	   that leaks every iteration and is never freed is invisible to LSan until
 *	   the process dies of it.  The same is true of a snapshot left on the
 *	   active stack, a transaction left open, or a resource owner left dangling
 *	   -- none of which LSan can see at all.
 *
 * This canary closes both gaps.  It samples cheap process-wide invariants at
 * the end of every iteration and compares them against a baseline taken once
 * the caches have settled.  Drift is reported *immediately*, naming the input
 * that caused it, which is the attribution LSan cannot give.
 *
 * It is not a replacement for LSan -- it cannot see a malloc that PostgreSQL
 * never parented into a context.  It is the complement: LSan catches
 * unreachable memory at exit, this catches reachable-but-growing state per
 * input.
 *
 * Portions Copyright (c) 1996-2024, PostgreSQL Global Development Group
 *
 *-------------------------------------------------------------------------
 */
#ifndef PG_FUZZ_CANARY_H
#define PG_FUZZ_CANARY_H

#include "postgres.h"

#include "access/xact.h"
#include "nodes/memnodes.h"
#include "utils/memutils.h"
#include "utils/snapmgr.h"

#include <stdio.h>
#include <time.h>
#include <stdlib.h>

/*
 * Iterations to run before taking the baseline.  The first inputs populate
 * catalog caches, the plan cache and the relcache, so measuring against
 * iteration zero would report every one of those as a leak.  Sixty-four is
 * enough for the caches a single-statement harness touches.
 */
#ifndef PGFUZZ_CANARY_WARMUP
#define PGFUZZ_CANARY_WARMUP 64
#endif

/*
 * Growth tolerated before a report, in bytes.  Not zero: PostgreSQL grows
 * caches lazily for a long time, and a canary that cries on every relcache
 * entry is a canary everyone switches off.  256 KB is far below what a real
 * per-iteration leak reaches within a few thousand inputs, and far above
 * ordinary cache settling.
 */
#ifndef PGFUZZ_CANARY_SLACK
#define PGFUZZ_CANARY_SLACK (256 * 1024)
#endif

/* Contexts may legitimately appear (a cached plan); a per-iteration leak does
 * not stop at eight. */
#ifndef PGFUZZ_CANARY_CTX_SLACK
#define PGFUZZ_CANARY_CTX_SLACK 8
#endif

typedef struct PgFuzzCanary
{
	Size		bytes;			/* allocated under TopMemoryContext, recursive */
	int			contexts;		/* live contexts in the whole tree */
	bool		snapshot_set;	/* ActiveSnapshotSet() */
	bool		in_xact;		/* IsTransactionState() */
} PgFuzzCanary;

/*
 * Iterations between suspecting a leak and confirming it.
 *
 * A single sample cannot tell an allocation that STAYS from one that was going
 * to happen once anyway. The first version of this reported on the first
 * sample and its very first firing was +1,079,360 bytes on vanilla PostgreSQL
 * -- a catalog cache filling, not a leak. Growth that is still there dozens of
 * inputs later is a different claim from growth observed once, and only the
 * first one is worth a human reading it.
 */
#ifndef PGFUZZ_CANARY_CONFIRM
#define PGFUZZ_CANARY_CONFIRM 32
#endif

static PgFuzzCanary pgfuzz_canary_base = {0, 0, false, false};
static uint64 pgfuzz_canary_iter = 0;

/*
 * Seconds between heartbeats. Short enough that any sane stall threshold is a
 * multiple of it, long enough to be invisible in a log: at 60s a 10-hour slice
 * adds 600 lines, against the millions libFuzzer prints.
 */
#define PGFUZZ_CANARY_BEAT 60
static time_t pgfuzz_canary_beat_at = 0;
static int	pgfuzz_canary_reports = 0;

/* Pending suspicion, awaiting confirmation. */
static int	pgfuzz_canary_confirms = 0;			/* how many times growth recurred */
static uint64 pgfuzz_canary_suspect_at = 0;		/* 0 = none pending */
static uint64 pgfuzz_canary_suspect_hash = 0;
static size_t pgfuzz_canary_suspect_size = 0;
static Size pgfuzz_canary_suspect_bytes = 0;
static int	pgfuzz_canary_suspect_ctx = 0;

/* Count every context in the tree.  memnodes.h exposes the links; there is no
 * public counter, and MemoryContextStats() prints rather than returns. */
static int
pgfuzz_canary_count_contexts(MemoryContext ctx)
{
	MemoryContext child;
	int			n = 1;

	if (ctx == NULL)
		return 0;
	for (child = ctx->firstchild; child != NULL; child = child->nextchild)
		n += pgfuzz_canary_count_contexts(child);
	return n;
}


/*
 * Signed delta, printed with an explicit sign.
 *
 * `now.bytes - base.bytes` is Size arithmetic: unsigned. When memory DROPS --
 * a cache evicted, a context reset between samples -- it wraps, and the leak
 * line reads
 *
 *     bytes 41175016 -> 40635624 (+18446744073709012224)
 *
 * which is 2^64 minus the real 539,392-byte decrease. Observed on
 * simple_query_fuzzer, 2026-08-29. The number is nonsense exactly when memory
 * is doing the interesting thing, and a reader who trusts it concludes the
 * opposite of the truth.
 */
static long long
pgfuzz_canary_delta(Size now, Size base)
{
	return (now >= base) ? (long long) (now - base)
						 : -(long long) (base - now);
}

static void
pgfuzz_canary_sample(PgFuzzCanary *out)
{
	out->bytes = MemoryContextMemAllocated(TopMemoryContext, true);
	out->contexts = pgfuzz_canary_count_contexts(TopMemoryContext);
	out->snapshot_set = ActiveSnapshotSet();
	out->in_xact = IsTransactionState();
}

/*
 * A cheap, stable identifier for the input, so a report can be tied back to the
 * exact bytes without printing them (they are arbitrary binary).  FNV-1a.
 */
static uint64
pgfuzz_canary_hash(const uint8_t *data, size_t size)
{
	uint64		h = UINT64CONST(0xcbf29ce484222325);
	size_t		i;

	for (i = 0; i < size; i++)
	{
		h ^= (uint64) data[i];
		h *= UINT64CONST(0x100000001b3);
	}
	return h;
}

/*
 * Call once from LLVMFuzzerInitialize(), after the backend is up.  Cheap: the
 * baseline is really taken later, once warmup has passed.
 */
static inline void
pgfuzz_canary_init(void)
{
	pgfuzz_canary_iter = 0;
	pgfuzz_canary_beat_at = 0;
	pgfuzz_canary_reports = 0;
	pgfuzz_canary_sample(&pgfuzz_canary_base);
}

/*
 * Call at the very end of LLVMFuzzerTestOneInput(), after the harness has done
 * its own cleanup -- the point of the check is that everything the iteration
 * touched should be gone by now.
 *
 * Reports to stderr and keeps going.  It deliberately does NOT abort: a
 * resource leak is a finding to record, not a reason to kill a run that is
 * still producing coverage, and aborting here would reintroduce exactly the
 * restart loop this was written to explain.
 */
static inline void
pgfuzz_canary_check(const uint8_t *data, size_t size)
{
	PgFuzzCanary now;
	bool		grew_bytes,
				grew_ctx;

	pgfuzz_canary_iter++;

	/*
	 * HEARTBEAT, on a fixed wall-clock cadence.
	 *
	 * libFuzzer's own progress lines come at DOUBLING intervals -- #1024,
	 * #2048, #4096 -- so the silence between them grows without bound. Measured
	 * on simple_query_fuzzer by differencing consecutive pulses, the
	 * #16384 -> #32768 interval took 1,821 seconds: longer than any stall
	 * threshold worth setting, while the target was working perfectly. There is
	 * no libFuzzer flag for the cadence (82 flags; none control it), so a
	 * watcher reading its output can never separate slow from stuck.
	 *
	 * This line closes that gap from inside: a fixed interval, independent of
	 * how many inputs have run, so silence means the iteration loop stopped
	 * turning and nothing else.
	 *
	 * It is deliberately NOT redundant with the CPU counter an external watcher
	 * reads. They fail in opposite directions: a target spinning in an infinite
	 * loop burns CPU and looks alive to the counter while this line stops; a
	 * target blocked on a socket stops burning CPU while its last heartbeat may
	 * still be recent. Neither alone is sufficient.
	 */
	{
		time_t		nowt = time(NULL);

		if (pgfuzz_canary_beat_at == 0)
			pgfuzz_canary_beat_at = nowt;
		else if (nowt - pgfuzz_canary_beat_at >= PGFUZZ_CANARY_BEAT)
		{
			pgfuzz_canary_beat_at = nowt;
			fprintf(stderr, "PGFUZZ HEARTBEAT: iteration %llu\n",
					(unsigned long long) pgfuzz_canary_iter);
			fflush(stderr);
		}
	}

	/* Re-baseline throughout warmup so caches settle into the baseline. */
	if (pgfuzz_canary_iter <= PGFUZZ_CANARY_WARMUP)
	{
		pgfuzz_canary_sample(&pgfuzz_canary_base);
		return;
	}

	pgfuzz_canary_sample(&now);

	grew_bytes = now.bytes > pgfuzz_canary_base.bytes + PGFUZZ_CANARY_SLACK;
	grew_ctx = now.contexts > pgfuzz_canary_base.contexts + PGFUZZ_CANARY_CTX_SLACK;

	/*
	 * State that must be clean between iterations regardless of growth.  A
	 * snapshot left on the active stack or a transaction left open means the
	 * next input runs in a state the corpus cannot reproduce -- which is the
	 * class of bug that makes crashes unreproducible.
	 */
	if (now.snapshot_set || now.in_xact)
	{
		fprintf(stderr,
				"PGFUZZ CANARY: iteration %llu left %s%s set -- input hash %016llx, %zu bytes\n",
				(unsigned long long) pgfuzz_canary_iter,
				now.snapshot_set ? "an active snapshot" : "",
				now.in_xact ? " an open transaction" : "",
				(unsigned long long) pgfuzz_canary_hash(data, size), size);
		pgfuzz_canary_reports++;
	}

	/*
	 * Confirmation, in two steps.
	 *
	 * Step 1: growth appears -- remember it and say nothing. Most growth at
	 * this point is a cache filling for the first time.
	 *
	 * Step 2: PGFUZZ_CANARY_CONFIRM iterations later, look again. Still
	 * elevated means it accumulated and did not come back, which is a leak.
	 * Back to normal means it was a one-off, and the new level becomes the
	 * baseline so the same cache is not re-reported forever.
	 */
	if (pgfuzz_canary_suspect_at != 0)
	{
		if (pgfuzz_canary_iter - pgfuzz_canary_suspect_at >= PGFUZZ_CANARY_CONFIRM)
		{
			if (now.bytes > pgfuzz_canary_base.bytes + PGFUZZ_CANARY_SLACK ||
				now.contexts > pgfuzz_canary_base.contexts + PGFUZZ_CANARY_CTX_SLACK)
			{
				/*
				 * Recurrence is the discriminator, not persistence.
				 *
				 * "Still elevated N iterations later" is satisfied forever by a
				 * cache that filled once and stays -- which is what the first
				 * version reported, twice, on vanilla PostgreSQL: +1,079,360
				 * bytes from one allocation per worker process, identical
				 * numbers, no accumulation.  A leak is different in kind: it
				 * confirms again and again, each time from a HIGHER baseline,
				 * because every input adds more.
				 *
				 * So the first confirmation is reported as growth, not as a
				 * leak, and only repeats are called a leak.  Getting this
				 * backwards produces a canary that reports normal warmup as a
				 * defect, which is worse than silence: it teaches everyone to
				 * ignore the one line that matters.
				 */
				pgfuzz_canary_confirms++;

				/*
				 * NAME THE CONTEXTS, once.
				 *
				 * Everything above counts: bytes, contexts, deltas. None of it
				 * says WHICH context is growing, and that is the only thing
				 * that decides what the leak is. On 2026-08-29 four targets --
				 * backend_types, extension_funcs, simple_query, spi_query --
				 * were all leaking ~23 contexts per input, and they are exactly
				 * the four that execute SQL against a live backend. That rules
				 * out any one target's harness code and leaves two candidates
				 * a counter cannot separate:
				 *
				 *	 growth under CacheMemoryContext -- PostgreSQL accumulating
				 *	 relcache/plan entries for unbounded distinct SQL, which is
				 *	 by design and is a backend-LIFETIME problem, not a bug;
				 *
				 *	 growth under a harness-created context -- something made
				 *	 per input and never deleted, which is ours to fix.
				 *
				 * MemoryContextStatsDetail prints the tree with names and
				 * sizes, so it answers that directly. Printed ONCE, at the
				 * third confirmation: by then a leak is established, and the
				 * dump is thousands of lines that must not repeat every input.
				 */
				if (pgfuzz_canary_confirms == 3)
				{
					fprintf(stderr, "PGFUZZ CANARY: context tree at leak "
							"confirmation 3 -- names identify the leak:\n");
					fflush(stderr);
					/*
					 * max_children must be LARGE. The first attempt passed 12
					 * and printed only small bounded caches -- Regexp, Operator
					 * lookup, Type information -- then summarised the rest as
					 * "321 more child contexts containing 5,793,968 bytes",
					 * which is the entire leak, discarded by the parameter that
					 * was supposed to keep the dump readable. A truncated dump
					 * of a leak names everything except the leak.
					 */
					/*
					 * PG16 has no max_level parameter: the signature is
					 * (context, max_children, print_to_stderr), and max_level
					 * was added in 17. Verified against each branch's own
					 * memutils.h rather than assumed from one -- checking the
					 * PG17 header and generalising is exactly what broke every
					 * PG16 build in the 2026-08-30 matrix campaign, all 18
					 * entries, fourteen minutes after launch.
					 */
#if PG_VERSION_NUM >= 170000
					MemoryContextStatsDetail(TopMemoryContext, 100, 2000, true);
#else
					MemoryContextStatsDetail(TopMemoryContext, 2000, true);
#endif
					fflush(stderr);
				}

				if (pgfuzz_canary_confirms >= 2)
					fprintf(stderr,
							"PGFUZZ CANARY: LEAK -- growth recurred (%d confirmations, "
							"baseline rising): bytes %zu -> %zu (%+lld), "
							"contexts %d -> %d (%+d). Latest input hash %016llx, %zu bytes\n",
							pgfuzz_canary_confirms,
							pgfuzz_canary_base.bytes, now.bytes,
							pgfuzz_canary_delta(now.bytes, pgfuzz_canary_base.bytes),
							pgfuzz_canary_base.contexts, now.contexts,
							now.contexts - pgfuzz_canary_base.contexts,
							(unsigned long long) pgfuzz_canary_suspect_hash,
							pgfuzz_canary_suspect_size);
				else
					fprintf(stderr,
							"PGFUZZ CANARY: one-time growth (not yet a leak) -- "
							"bytes %zu -> %zu (%+lld), contexts %d -> %d (%+d). "
							"Input hash %016llx, %zu bytes\n",
							pgfuzz_canary_base.bytes, now.bytes,
							pgfuzz_canary_delta(now.bytes, pgfuzz_canary_base.bytes),
							pgfuzz_canary_base.contexts, now.contexts,
							now.contexts - pgfuzz_canary_base.contexts,
							(unsigned long long) pgfuzz_canary_suspect_hash,
							pgfuzz_canary_suspect_size);
				pgfuzz_canary_reports++;
			}
			/*
			 * Re-baseline either way. Confirmed, so the next distinct leak is
			 * not buried under this one; or transient, so the settled cache
			 * becomes the new normal.
			 */
			pgfuzz_canary_base = now;
			pgfuzz_canary_suspect_at = 0;
		}
		return;					/* one suspicion at a time */
	}

	if (grew_bytes || grew_ctx)
	{
		pgfuzz_canary_suspect_at = pgfuzz_canary_iter;
		pgfuzz_canary_suspect_hash = pgfuzz_canary_hash(data, size);
		pgfuzz_canary_suspect_size = size;
		pgfuzz_canary_suspect_bytes = now.bytes;
		pgfuzz_canary_suspect_ctx = now.contexts;
		(void) pgfuzz_canary_suspect_bytes;		/* kept for debugging */
		(void) pgfuzz_canary_suspect_ctx;
	}
}

#endif							/* PG_FUZZ_CANARY_H */

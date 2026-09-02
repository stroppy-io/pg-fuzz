/*-------------------------------------------------------------------------
 *
 * fuzz_probe.h
 *	  Probes that prove the harness is still doing what it claims.
 *
 * Every probe here exists because a target once looked healthy while testing
 * nothing, and no signal anywhere said so.  They are deliberately *not*
 * diagnostics: each one is meant to be wired to something that FAILS -- a
 * smoke test, a build gate, a run gate.  The project's own rule, learned the
 * expensive way: enforcement beats diagnosis, because a correct warning inside
 * a 6,000-line log is indistinguishable from silence.
 *
 * They are also all off by default and driven by the environment, so a probe
 * costs a `getenv` per process in a normal run and nothing else.  A probe that
 * changes behaviour when nobody asked is a new source of the very confusion it
 * is meant to remove.
 *
 * THE RULE THIS FILE ENCODES
 * =========================
 * A probe that has never been SEEN TO FAIL has not been tested.  Each one
 * below names how to make it fail on purpose, and that check belongs in the
 * smoke test next to the check itself -- on 2026-08-16 a watchdog written to
 * prevent a silent stall passed review and then caused one, because only the
 * condition it detects had been tested, never the mechanism.
 *
 *-------------------------------------------------------------------------
 */
#ifndef PG_FUZZ_PROBE_H
#define PG_FUZZ_PROBE_H

#include <stdio.h>
#include <stdlib.h>

/*
 * PROBE 1 -- is leak detection actually live on this target?
 *
 * PGFUZZ_LEAK_CANARY=1 leaks 1234 bytes on the first input and nothing after.
 * Under an ASan build with leak detection on, the target MUST die reporting
 * "Direct leak of 1234 byte(s)".  A target that survives is a target running
 * with leak detection off -- which is exactly what an unbalanced
 * __lsan_disable() would cause, and it is the worst failure in this project's
 * catalogue: every leak the campaign was supposed to find would be silently
 * absent while the run reported success.
 *
 * The size is deliberately odd so it cannot be confused with a PostgreSQL
 * allocation: no context, block or chunk in the tree is 1234 bytes.
 *
 * Once per process, not per input: libFuzzer stops at the first report anyway,
 * and leaking per input would bury a real finding under canary noise if the
 * variable were ever left set.
 */
static inline void
pgfuzz_probe_leak_canary(void)
{
	static int	fired = 0;
	const char *v;

	if (fired)
		return;
	fired = 1;

	v = getenv("PGFUZZ_LEAK_CANARY");
	if (v == NULL || v[0] != '1')
		return;

	/*
	 * Allocate, then DROP the only reference.
	 *
	 * The clearing store is the whole probe. The first version of this kept
	 * the pointer in `static void *volatile sink` and called it "deliberately
	 * dropped" in a comment -- but a static is a root LSan scans, so the chunk
	 * stayed reachable, nothing was reported, and the probe accused three
	 * healthy targets of running with leak detection off. A canary that does
	 * not leak tests nothing, which is the same defect it exists to catch.
	 *
	 * volatile on both stores: the allocation must actually happen, and the
	 * clear must not be optimized away as dead.
	 */
	{
		static void *volatile sink;

		sink = malloc(1234);
		sink = NULL;
	}
	fprintf(stderr, "PGFUZZ PROBE: leak canary armed (1234 bytes leaked)\n");
}

/*
 * PROBE 2 -- did this target actually consume the input it was given?
 *
 * Call at the end of an iteration with how many bytes were read.  A target
 * that is handed 100 bytes and reads 1 is not fuzzing the format it claims to
 * fuzz, and the execution counter cannot tell the difference -- it counts
 * inputs offered, not bytes used.
 *
 * This is not hypothetical.  protocol_fuzzer consumed exactly one byte of
 * every input for the life of the project: __wrap_pq_getbyte returned
 * buffer[0] every call (the walking pointer was incremented and never
 * dereferenced), and only pq_getbyte was wrapped, so the message length and
 * body went to the real pq_recvbuf, which fails with "there is no client
 * connection" because the harness builds no Port.  It was recorded as
 * REPAIRED on the strength of executions rising from 1 to millions.  The
 * measured signature, visible the whole time: 2,905,390 executions at cov 380,
 * beside a target reaching 23,328 edges in 121 executions.
 *
 * PGFUZZ_REQUIRE_CONSUMED=1 makes short reads fatal.  Default is a one-line
 * report on stderr, because a target may legitimately reject an input early
 * (too long, wrong magic) -- the smoke test decides what is acceptable, not
 * this header.
 */
static inline void
pgfuzz_probe_consumed(const char *target, size_t offered, size_t consumed)
{
	const char *v;

	if (offered == 0)
		return;

	/*
	 * When PGFUZZ_PROBE_CONSUMED=1 the line is printed even for a FULL read.
	 *
	 * That is not verbosity, it is the difference between "this target read
	 * everything" and "this probe is not compiled into this build" -- which
	 * are indistinguishable if the probe only speaks up on failure. A checker
	 * that reads silence as success is the exact defect this file exists to
	 * catch, and the first version of it had precisely that bug.
	 */
	v = getenv("PGFUZZ_PROBE_CONSUMED");
	if (consumed >= offered && (v == NULL || v[0] != '1'))
		return;

	/*
	 * Rate-limit, do not silence.
	 *
	 * A target whose parser legitimately stops early reports a short read on
	 * EVERY input. protocol_fuzzer does exactly that -- feeding garbage to a
	 * wire protocol means the parser stops as soon as the framing is wrong --
	 * and at a few thousand executions a second this one line was 48% of a
	 * 310 MB slice log. Every gate that greps a slice log paid for it.
	 *
	 * Removing the line is not the fix: the comment above is right that a
	 * probe which only speaks on failure cannot be distinguished from one that
	 * was never compiled in. So keep the first PROBE_LOUD occurrences verbatim
	 * -- enough that anyone reading the head of a log sees the probe is alive
	 * and what it found -- then report one line per PROBE_EVERY occurrences,
	 * carrying the running count so the volume is still visible as a number
	 * rather than as bulk.
	 *
	 * PGFUZZ_PROBE_CONSUMED=1 restores every-input reporting, for when that is
	 * the thing being investigated.
	 */
	{
		static unsigned long short_reads = 0;
		const unsigned long PROBE_LOUD  = 10;
		const unsigned long PROBE_EVERY = 10000;
		int verbose = (v != NULL && v[0] == '1');

		short_reads++;

		if (verbose || short_reads <= PROBE_LOUD)
		{
			fprintf(stderr,
					"PGFUZZ PROBE: %s consumed %zu of %zu byte(s) (%.1f%%)\n",
					target, consumed, offered,
					offered ? (100.0 * (double) consumed / (double) offered) : 0.0);
		}
		else if (short_reads % PROBE_EVERY == 0)
		{
			fprintf(stderr,
					"PGFUZZ PROBE: %s short read #%lu (latest %zu of %zu byte(s), %.1f%%)\n",
					target, short_reads, consumed, offered,
					offered ? (100.0 * (double) consumed / (double) offered) : 0.0);
		}
	}

	if (consumed >= offered)
		return;

	v = getenv("PGFUZZ_REQUIRE_CONSUMED");
	if (v != NULL && v[0] == '1')
	{
		fprintf(stderr,
				"PGFUZZ PROBE: FATAL -- %s is not reading its input\n", target);
		abort();
	}
}

/*
 * PROBE 3 -- does a fatal error say anything at all?
 *
 * PGFUZZ_FATAL_CANARY=1 raises a deliberate FATAL on the first input.  Its
 * text MUST reach stderr.  If it does not, every crash this target ever
 * reports arrives with no PostgreSQL diagnostic attached -- no message, no
 * statement -- and triage starts from a bare stack.
 *
 * That is the state add_fuzzers.diff leaves the tree in.  Its elog.c hunk
 * #ifdefs out EmitErrorReport() to silence the flood of routine rejections,
 * which is reasonable; but errfinish() reaches that call only for NON-ERROR
 * levels, because elevel == ERROR returns earlier through PG_RE_THROW().  So
 * the suppression covers WARNING/NOTICE/LOG as intended -- and FATAL and PANIC
 * as well, which was not.  A PANIC reaches libFuzzer with zero text.
 *
 * Guarded on FATAL being defined (elog.h) so the frontend targets, which never
 * see PostgreSQL's headers, still compile.
 */
#ifdef FATAL
static inline void
pgfuzz_probe_fatal_canary(void)
{
	static int	fired = 0;
	const char *v;

	if (fired)
		return;
	fired = 1;

	v = getenv("PGFUZZ_FATAL_CANARY");
	if (v == NULL || v[0] != '1')
		return;

	fprintf(stderr, "PGFUZZ PROBE: raising deliberate FATAL\n");
	elog(FATAL, "pgfuzz probe: deliberate FATAL, its text must be visible");
}
#endif							/* FATAL */


/*
 * PROBE 7 -- why was this input rejected?
 *
 * PGFUZZ_SHOW_ERRORS=1 prints the ERROR that a target caught, on the longjmp
 * path, before FlushErrorState() throws it away.
 *
 * Off by default and it must stay that way: a fuzz target rejects the
 * overwhelming majority of its inputs, which is the whole reason
 * add_fuzzers.diff suppresses EmitErrorReport in the first place.
 *
 * But that suppression is total, and ERROR never reaches EmitErrorReport at
 * all -- errfinish() returns earlier through PG_RE_THROW() for elevel ==
 * ERROR. So when a target silently does nothing there is no way to ask it why,
 * and this project has twice spent hours inferring an answer that one line of
 * error text would have given: protocol_fuzzer connecting to a database that
 * did not exist, and simple_query_fuzzer executing a 20-million-row
 * aggregation in 8ms.
 *
 * Call it from the error branch, before FlushErrorState().
 */
#ifdef FATAL
static inline void
pgfuzz_probe_show_error(const char *target)
{
	const char *v = getenv("PGFUZZ_SHOW_ERRORS");
	ErrorData  *e;
	MemoryContext octx;

	if (v == NULL || v[0] != '1')
		return;

	/*
	 * CopyErrorData() must run in a context that is not the error context it
	 * is copying out of, and it asserts as much.
	 */
	octx = MemoryContextSwitchTo(TopMemoryContext);
	e = CopyErrorData();
	fprintf(stderr, "PGFUZZ ERROR [%s]: %s%s%s\n",
			target,
			e->message ? e->message : "(no message)",
			e->detail ? " | detail: " : "",
			e->detail ? e->detail : "");
	FreeErrorData(e);
	MemoryContextSwitchTo(octx);
}
#endif							/* FATAL */

#endif							/* PG_FUZZ_PROBE_H */

/*-------------------------------------------------------------------------
 *
 * fuzz_timeout.h
 *	  A statement deadline that actually fires.
 *
 * THE DEFECT THIS REPLACES
 * =======================
 * fuzzer_initialize.c sets statement_timeout=10s at PGC_S_OVERRIDE and a
 * comment claims it "uses PostgreSQL's own timeout machinery, which works
 * precisely because it owns the signal".  Both halves are false, and the
 * result is that NOTHING bounds a single input on spi_query_fuzzer,
 * simple_query_fuzzer or backend_types_fuzzer.
 *
 *   1. STATEMENT_TIMEOUT is never ARMED.  The only site that arms it is
 *      enable_statement_timeout(), which is static to postgres.c and called
 *      only from start_xact_command().  Every harness calls
 *      StartTransactionCommand() directly, so that path never runs.  Setting
 *      the GUC configures a timeout that is never started.
 *
 *   2. SIGALRM belongs to libFuzzer.  InitializeTimeouts() runs inside
 *      LLVMFuzzerInitialize; libFuzzer installs fuzzer::AlarmHandler after
 *      that returns, overwriting handle_sig_alarm.  Arming a PostgreSQL
 *      timeout then delivers its signal to libFuzzer's handler, which knows
 *      nothing about it -- and replaces libFuzzer's own repeating timer with
 *      our one-shot, so -timeout stops working too.  Two mechanisms, one
 *      clock, neither firing.
 *
 * Measured, not argued: `SELECT pg_sleep(30);` ran for 61 seconds against a
 * configured 10-second statement_timeout.  scripts/probe-harness.sh --timeout
 * is that measurement, and it is the check this header has to turn green.
 *
 * WHY NOT JUST RE-REGISTER STATEMENT_TIMEOUT
 * ==========================================
 * Reclaiming the signal requires InitializeTimeouts(), which is re-entrant by
 * design but CLEARS the registration table -- so the builtin timeouts that
 * InitPostgres registered are gone afterwards, and StatementTimeoutHandler is
 * static to postgres.c and cannot be re-registered from here.  So we register
 * our own USER_TIMEOUT with a handler that sets the same two flags the real
 * one does.  CHECK_FOR_INTERRUPTS() cannot tell the difference, which is the
 * point.
 *
 * WHAT THIS COSTS
 * ===============
 * libFuzzer's -timeout, which had no working clock in these harnesses anyway.
 * A deadline that fires is worth more than one that does not.
 *
 *-------------------------------------------------------------------------
 */
#ifndef PG_FUZZ_TIMEOUT_H
#define PG_FUZZ_TIMEOUT_H

#include "miscadmin.h"
#include "utils/timeout.h"

/* Overridable so the probe can prove the deadline moves. */
#ifndef PGFUZZ_STMT_TIMEOUT_MS
#define PGFUZZ_STMT_TIMEOUT_MS 10000
#endif

static TimeoutId pgfuzz_stmt_timeout_id = MAX_TIMEOUTS;

/*
 * Set exactly what PostgreSQL's own statement timeout sets.  The next
 * CHECK_FOR_INTERRUPTS() raises ERROR "canceling statement due to statement
 * timeout" and the harness's normal error path unwinds it.
 *
 * Nothing else belongs in a signal handler: no palloc, no ereport, no I/O.
 */
static void
pgfuzz_stmt_timeout_handler(void)
{
	InterruptPending = true;
	QueryCancelPending = true;
	SetLatch(MyLatch);			/* wake pg_sleep and other latch waits */
}

/*
 * Take the clock back from libFuzzer and register our deadline.  Idempotent;
 * call it on the first input, not during initialization -- libFuzzer installs
 * its handler after LLVMFuzzerInitialize returns, so doing this any earlier is
 * precisely the bug being fixed.
 */
static inline void
pgfuzz_timeout_reclaim(void)
{
	static bool done = false;

	if (done)
		return;
	done = true;

	InitializeTimeouts();		/* reinstalls handle_sig_alarm; clears the table */
	pgfuzz_stmt_timeout_id = RegisterTimeout(USER_TIMEOUT,
											 pgfuzz_stmt_timeout_handler);
}

/* Arm it.  Call immediately after StartTransactionCommand(). */
static inline void
pgfuzz_timeout_arm(void)
{
	if (pgfuzz_stmt_timeout_id == MAX_TIMEOUTS)
		return;
	enable_timeout_after(pgfuzz_stmt_timeout_id, PGFUZZ_STMT_TIMEOUT_MS);
}

/*
 * Disarm, and clear the flags.
 *
 * The clearing is not tidiness.  If the deadline fires in the window between
 * the statement finishing and the timeout being disabled, QueryCancelPending
 * survives into the NEXT iteration and cancels an unrelated input at its first
 * CHECK_FOR_INTERRUPTS -- a "canceling statement" attributed to the wrong
 * input, which is the hardest kind of false report to trace back.
 * PostgresMain clears both at postgres.c:4474 for exactly this reason;
 * extension_funcs_fuzzer currently does not, and should.
 *
 * Call on EVERY exit path, success and error alike.
 */
static inline void
pgfuzz_timeout_disarm(void)
{
	if (pgfuzz_stmt_timeout_id != MAX_TIMEOUTS)
		disable_timeout(pgfuzz_stmt_timeout_id, false);
	QueryCancelPending = false;
	InterruptPending = false;
}

#endif							/* PG_FUZZ_TIMEOUT_H */

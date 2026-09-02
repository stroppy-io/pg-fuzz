/*-------------------------------------------------------------------------
 *
 * fuzz_deadline.h
 *	  A per-input deadline for targets where the timeout table is unusable.
 *
 * WHY NOT fuzz_timeout.h
 * ======================
 * That header reclaims SIGALRM and registers a USER_TIMEOUT, and it works --
 * on targets that own their initialisation.  protocol_fuzzer does not.  It
 * calls PostgresMain() PER INPUT, and PostgresMain's startup calls
 * InitializeTimeouts(), which CLEARS the registration table.  A handler
 * registered before it is gone by the time enable_timeout_after() runs:
 *
 *     Assert(all_timeouts[id].timeout_handler != NULL)      timeout.c:165
 *
 * Three attempts to place a registration either side of PostgresMain aborted,
 * and the target was left with no deadline at all -- costing ~7,110 seconds of
 * a sweep slot whenever an input reaches orafce's dbms_alert.waitany().
 *
 * WHAT THIS DOES INSTEAD
 * ======================
 * Nothing that PostgreSQL owns.  One long-lived thread holds a deadline
 * timestamp; when it passes, the thread sets the two flags a cancel would set
 * and wakes the latch:
 *
 *     InterruptPending  = true;
 *     QueryCancelPending = true;
 *     SetLatch(MyLatch);
 *
 * CHECK_FOR_INTERRUPTS() cannot tell that apart from a real query cancel, and
 * every blocking path this needs to break already calls it:
 *
 *   - the regex engine, via  #define INTERRUPT(re) CHECK_FOR_INTERRUPTS()
 *     (regcustom.h:55), which is what bounds catastrophic backtracking
 *   - ConditionVariableTimedSleep -> WaitLatch, which is where
 *     dbms_alert.waitany() parks; SetLatch is what makes it look
 *
 * The resulting ereport(ERROR) unwinds into the harness's own sigsetjmp, so a
 * timed-out input is discarded exactly like any other erroring input.
 *
 * ONE THREAD, NOT ONE PER INPUT.  regex_fuzzer runs thousands of inputs a
 * second; pthread_create per input would cost more than the hangs.  Arming is
 * two stores.  The 100 ms poll is far finer than any deadline worth setting.
 *
 * SetLatch from another thread is the same contract signal handlers use, and
 * MyLatch is NULL in targets with no backend (regex_fuzzer), so it is guarded.
 *
 *-------------------------------------------------------------------------
 */
#ifndef FUZZ_DEADLINE_H
#define FUZZ_DEADLINE_H

#include <pthread.h>
#include <signal.h>
#include <time.h>

#include "miscadmin.h"
#include "storage/latch.h"

#ifndef PGFUZZ_DEADLINE_MS
#define PGFUZZ_DEADLINE_MS 10000
#endif

static volatile sig_atomic_t pgfuzz_dl_armed = 0;
static volatile long long pgfuzz_dl_at_ms = 0;
static volatile sig_atomic_t pgfuzz_dl_fired = 0;
static pthread_t pgfuzz_dl_thread;
static int pgfuzz_dl_started = 0;

static inline long long
pgfuzz_dl_now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (long long) ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void *
pgfuzz_dl_main(void *arg)
{
	(void) arg;
	for (;;)
	{
		struct timespec nap = {0, 100 * 1000 * 1000};	/* 100 ms */

		nanosleep(&nap, NULL);

		if (!pgfuzz_dl_armed)
			continue;
		if (pgfuzz_dl_now_ms() < pgfuzz_dl_at_ms)
			continue;

		/*
		 * Disarm FIRST.  If the cancel does not take -- a path that never
		 * reaches CHECK_FOR_INTERRUPTS -- this must not spin setting flags
		 * for the rest of the run.
		 */
		pgfuzz_dl_armed = 0;
		pgfuzz_dl_fired = 1;

		InterruptPending = true;
		QueryCancelPending = true;
		if (MyLatch != NULL)
			SetLatch(MyLatch);
	}
	return NULL;
}

/* Start the watcher once.  Safe to call from LLVMFuzzerInitialize. */
static inline void
pgfuzz_deadline_init(void)
{
	if (pgfuzz_dl_started)
		return;
	if (pthread_create(&pgfuzz_dl_thread, NULL, pgfuzz_dl_main, NULL) == 0)
	{
		pthread_detach(pgfuzz_dl_thread);
		pgfuzz_dl_started = 1;
	}
}

static inline void
pgfuzz_deadline_arm(void)
{
	if (!pgfuzz_dl_started)
		return;
	pgfuzz_dl_fired = 0;
	pgfuzz_dl_at_ms = pgfuzz_dl_now_ms() + PGFUZZ_DEADLINE_MS;
	pgfuzz_dl_armed = 1;
}

static inline void
pgfuzz_deadline_disarm(void)
{
	pgfuzz_dl_armed = 0;
}

/* Did the last input time out?  For the probe, and for reporting. */
static inline int
pgfuzz_deadline_expired(void)
{
	return pgfuzz_dl_fired != 0;
}

#endif							/* FUZZ_DEADLINE_H */

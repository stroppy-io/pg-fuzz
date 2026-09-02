/*-------------------------------------------------------------------------
 *
 * spi_query_fuzzer.c
 *	  Fuzz whole SQL statements against a real, initialized backend.
 *
 * This is the deep target.  FuzzerInitialize() boots an actual backend
 * against a copy of the data directory that initdb produced at build time, so
 * unlike the standalone harnesses this one has a catalog: names resolve,
 * types resolve, the planner can see statistics, and the executor actually
 * runs.  Everything from the parser through analysis, rewriting, planning and
 * execution is reachable from a single input.
 *
 * That reach is exactly why the upstream simple_query_fuzzer, which has no
 * backend, cannot go past the front of the analyzer: without a catalog every
 * statement that names anything errors out immediately.
 *
 * Each iteration runs inside its own transaction which is always aborted, so
 * a CREATE TABLE in input N is not visible to input N+1.  Without that the
 * corpus would slowly mutate the database into a state no other run can
 * reproduce, and every crash would be unreproducible.
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include "access/xact.h"
#include "executor/spi.h"
#include "miscadmin.h"
#include "tcop/tcopprot.h"
#include "utils/memutils.h"
/* PortalContext */
#include "utils/portal.h"
#include "utils/snapmgr.h"

#include <setjmp.h>
#include <stdlib.h>
#include <string.h>

#include "fuzz_canary.h"
#include "fuzz_probe.h"
#include "fuzz_timeout.h"
#include "fuzz_lineage.h"

/* fuzz_orphan.c -- names a leaked context instead of trusting ASan's stack */
extern void pgfuzz_orphan_begin(void);
extern long pgfuzz_orphan_end(void);

/* provided by fuzzer_initialize.c */
extern int	FuzzerInitialize(char *dbname, char ***argv);

/*
 * Statements that would run for an unbounded time or consume the machine are
 * not interesting findings, they are just budget disappearing.  A statement
 * timeout would be the principled fix, but it needs the timeout
 * infrastructure and a signal handler in a process libFuzzer also wants to
 * control; capping the input length is cruder and good enough.
 */
#define MAX_QUERY_LEN 4096

/*
 * PGFUZZ_PORTAL=1 runs each statement with a real PortalContext established.
 *
 * WHY THIS TOGGLE EXISTS
 * ======================
 * This harness calls SPI_execute() with no portal open, so PortalContext is
 * whatever it happened to be.  A real client never does that: a statement
 * arrives, a portal is created, and PortalContext points at that portal's
 * memory for the duration.
 *
 * That difference is not cosmetic, and on 2026-08-15 it became the whole
 * question.  ExecVacuum() allocates its cross-transaction context with
 *
 *     vac_context = AllocSetContextCreate(PortalContext, "Vacuum", ...);
 *
 * and upstream's comment right above it says this needs no abort cleanup
 * *because* it is a child of PortalContext.  With no portal, that parent is not
 * what upstream assumes, an ERROR longjmps past the MemoryContextDelete, and
 * 8192 bytes are orphaned -- which is exactly the leak found on OrioleDB's
 * fork.
 *
 * So "does this reproduce with a portal?" decides whether the finding is a
 * client-reachable memory leak or an artifact of how the harness drives the
 * backend.  Answering it by measurement rather than argument is the point:
 *
 *     PGFUZZ_PORTAL=1 ./spi_query_fuzzer <reproducer>
 *
 * Runtime rather than compile-time so one build answers both questions, and
 * off by default so the harness keeps reaching the paths it reaches today.
 */
static long pgfuzz_unexecuted = 0;
static bool pgfuzz_use_portal = false;

int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
	FuzzerInitialize("spi_query_db", argv);
	pgfuzz_canary_init();

	pgfuzz_use_portal = (getenv("PGFUZZ_PORTAL") != NULL &&
						 getenv("PGFUZZ_PORTAL")[0] == '1');

	/*
	 * Say which mode this is, once, in the target's own output.  A run log that
	 * does not record the deviations the harness is running under cannot be
	 * compared against another run log, and this one changes whether a whole
	 * class of finding reproduces.
	 */
	/*
	 * The deviation list, machine-readable and COMPLETE.
	 *
	 * The old line named three deviations and was accurate. It was also
	 * materially incomplete, and the omissions are the ones that decide
	 * whether a finding reproduces on a real server:
	 *
	 *   isTopLevel=false      SPI is atomic here, so _SPI_execute_plan passes
	 *                         PROCESS_UTILITY_QUERY and standard_ProcessUtility
	 *                         derives isTopLevel = false (utility.c:550). Every
	 *                         PreventInTransactionBlock statement therefore
	 *                         errors -- VACUUM, CREATE DATABASE, CREATE INDEX
	 *                         CONCURRENTLY, REINDEX, CLUSTER, DISCARD ALL. That
	 *                         is not a footnote: it is the exact path that
	 *                         reaches the ExecVacuum leak, so a report built on
	 *                         this harness has to say so.
	 *   no-active-portal      PGFUZZ_PORTAL=1 sets PortalContext ONLY.
	 *                         ActivePortal stays NULL and isTopLevel stays
	 *                         false, so that experiment answers "is this caused
	 *                         by the missing portal context" and NOT "does this
	 *                         reproduce on a real server".
	 *   commit-unreachable    the transaction is always aborted, so
	 *                         CommitTransaction, pre-commit triggers, deferred
	 *                         constraint checks and commit WAL are unreachable.
	 *   snapshot-forced       exec_simple_query pushes a snapshot only when
	 *                         analyze_requires_snapshot(); we push
	 *                         unconditionally, because EnsurePortalSnapshotExists
	 *                         would error without one.
	 *   not-client-backend    MyBackendType is forced to B_BACKEND with no
	 *                         postmaster and no MyProcPort -- a combination no
	 *                         real PostgreSQL process is in. Parallel workers
	 *                         cannot launch, so parallel plans degrade to serial
	 *                         silently.
	 *
	 * stmt-timestamp is reported from MEASURED state at the end of the run, not
	 * asserted here, so this line cannot drift away from what the code does.
	 */
	fprintf(stderr,
			"PGFUZZ DEVIATIONS: spi-atomic,isTopLevel=false,no-active-portal,"
			"xact-aborted,commit-unreachable,snapshot-forced,no-client-socket,"
			"not-client-backend,portal-ctx=%s\n",
			pgfuzz_use_portal ? "on" : "off");
	return 0;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	sigjmp_buf	local_sigjmp_buf;
	char	   *query;

	/*
	 * Per-iteration stack base for check_stack_depth(); see the long note in
	 * fuzz_util.h:pgfuzz_run().  FuzzerInitialize() -> InitStandaloneProcess()
	 * already recorded one, but on the initialization frame, which handed the
	 * guard a constant offset as extra budget and let runaway recursion reach
	 * the real stack limit instead of erroring out.
	 */
	set_stack_base();

	pgfuzz_probe_leak_canary();

	/*
	 * Take SIGALRM back from libFuzzer, once, HERE and not in
	 * LLVMFuzzerInitialize -- libFuzzer installs its handler after
	 * initialization returns, so reclaiming any earlier is the bug.
	 */
	pgfuzz_timeout_reclaim();

	pgfuzz_probe_fatal_canary();

	if (size == 0 || size > MAX_QUERY_LEN)
		return 0;

	query = (char *) malloc(size + 1);
	if (query == NULL)
		return 0;
	memcpy(query, data, size);
	query[size] = '\0';

	if (sigsetjmp(local_sigjmp_buf, 0) == 0)
	{
		PG_exception_stack = &local_sigjmp_buf;
		error_context_stack = NULL;

		pgfuzz_orphan_begin();
		StartTransactionCommand();
		pgfuzz_timeout_arm();
		PushActiveSnapshot(GetTransactionSnapshot());

		/*
		 * Stand in for the portal a real client statement would run inside.
		 *
		 * Not a full CreatePortal(): the point is the memory context, since
		 * that is what code like ExecVacuum() parents its allocations to.  A
		 * context under TopTransactionContext has the lifetime a portal's does
		 * for this purpose -- it is destroyed by the transaction abort below,
		 * which is precisely the cleanup upstream relies on and which the
		 * portal-less path does not provide.
		 */
		if (pgfuzz_use_portal)
			PortalContext = AllocSetContextCreate(TopTransactionContext,
												  "PgFuzz Portal",
												  ALLOCSET_DEFAULT_SIZES);

		/*
		 * A real backend stamps every statement (postgres.c:4776, before
		 * exec_simple_query).  Without it stmtStartTimestamp stays 0 and
		 * StartTransaction copies that into xactStartTimestamp, so now(),
		 * transaction_timestamp() and statement_timestamp() all return
		 * 2000-01-01 00:00:00+00 in every iteration -- forever, identically.
		 * Any finding involving time arithmetic was suspect in both
		 * directions, and nothing asserted it.
		 */
		SetCurrentStatementStartTimestamp();

		/*
		 * Report it from MEASURED state, once.
		 *
		 * A hand-written deviation list drifts away from the code the moment
		 * anyone edits either one, and the drift is invisible. This line is
		 * derived from the running backend, so if the call above is ever
		 * removed the probe goes red instead of the list quietly lying.
		 */
		{
			static bool ts_reported = false;

			if (!ts_reported)
			{
				ts_reported = true;
				fprintf(stderr, "PGFUZZ DEVIATION-CHECK: stmt-timestamp=%s\n",
						GetCurrentStatementStartTimestamp() != 0 ? "set" : "UNSET");
			}
		}

		if (SPI_connect() == SPI_OK_CONNECT)
		{
			int			spirc = SPI_execute(query, false, 0);

			/*
			 * Do not discard this.  SPI refuses two whole statement classes
			 * outright -- SPI_ERROR_TRANSACTION for BEGIN/COMMIT/ROLLBACK/
			 * SAVEPOINT (spi.c:2646) and SPI_ERROR_COPY for COPY ... FROM
			 * STDIN (spi.c:2636) -- and returns without executing anything.
			 * Discarding the code made "refused" and "ran clean" the same
			 * observation, so the corpus could accumulate transaction-control
			 * inputs that had never once run.
			 */
			if (spirc == SPI_ERROR_TRANSACTION || spirc == SPI_ERROR_COPY)
				pgfuzz_unexecuted++;

			SPI_finish();
		}

		if (pgfuzz_use_portal)
			PortalContext = NULL;

		(void) pgfuzz_orphan_end();
		pgfuzz_timeout_disarm();
		PopActiveSnapshot();

		/*
		 * Always abort, never commit: see the file header.  AbortCurrent-
		 * TransactionCommand also unwinds SPI and any snapshot we left.
		 */
		AbortCurrentTransaction();
	}
	else
	{
		/* the statement raised an ERROR -- the normal case */
		pgfuzz_probe_show_error("spi_query_fuzzer");
		(void) pgfuzz_orphan_end();
		pgfuzz_timeout_disarm();
		MemoryContextSwitchTo(TopMemoryContext);
		FlushErrorState();
		AbortCurrentTransaction();

		/*
		 * The error path is the one that matters here: this is where the
		 * longjmp skipped the cleanup, and where anything parented to the
		 * portal has to be released.  AbortCurrentTransaction() has already
		 * destroyed the context itself, so only the pointer needs clearing --
		 * leaving it dangling would hand the next iteration a freed context.
		 */
		if (pgfuzz_use_portal)
			PortalContext = NULL;
	}

	PG_exception_stack = NULL;
	error_context_stack = NULL;

	MemoryContextSwitchTo(TopMemoryContext);
	MemoryContextReset(MessageContext);

	free(query);

	/*
	 * After our own cleanup, not before: the check asks whether everything this
	 * iteration touched is actually gone, so it has to run once the harness
	 * believes it has tidied up.
	 */
	pgfuzz_canary_check(data, size);
	return 0;
}

// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
///////////////////////////////////////////////////////////////////////////////

#include "postgres.h"

#include "access/xlog.h"
#include "access/xact.h"
#include "common/username.h"
#include "executor/spi.h"
#include "jit/jit.h"
#include "libpq/libpq.h"
#include "libpq/pqsignal.h"
#include "miscadmin.h"
#include "nodes/parsenodes.h"
#include "optimizer/optimizer.h"
#include "parser/analyze.h"
#include "parser/parser.h"
#include "storage/proc.h"
#include "tcop/dest.h"
#include "tcop/pquery.h"
#include "tcop/tcopprot.h"
#include "tcop/utility.h"
#include "utils/portal.h"
#include "utils/datetime.h"
#include "utils/memutils.h"
/* pg_initialize_timing(); PostgreSQL 19 and later */
#include "portability/instr_time.h"
#include "utils/portal.h"
#include "utils/snapmgr.h"
#include "utils/timeout.h"

static void exec_simple_query(const char *query_string) {
  MemoryContext oldcontext;
  List *parsetree_list;
  ListCell *parsetree_item;

  /*
   * postgres.c:1026.  elog.c reads this to print the "STATEMENT:" line under
   * an ERROR or a TRAP, so without it a crash report never says which SQL
   * produced it -- which is precisely why every assertion chased today had to
   * be tied back to its input by hand.
   *
   * Cleared on both exits: at the end of this function, and in the error path
   * of LLVMFuzzerTestOneInput before the buffer is freed.  A dangling pointer
   * here would have the next report quote freed memory.
   */
  debug_query_string = query_string;

  oldcontext = MemoryContextSwitchTo(MessageContext);
  /*
   * RAW_PARSE_DEFAULT, not RAW_PARSE_TYPE_NAME.
   *
   * RAW_PARSE_TYPE_NAME parses a *type name* and returns a one-element List
   * containing a TypeName node -- which the loop below then hands to
   * lfirst_node(RawStmt, ...).  That is a guaranteed type confusion for every
   * input that parses at all, so under --enable-cassert the target died in
   * castNodeImpl() before reaching the analyzer, and in a release build it
   * would pass a TypeName to pg_analyze_and_rewrite_fixedparams() as a
   * RawStmt.
   *
   * The practical consequence is that this target has never fuzzed a SQL
   * statement: everything past the raw parser was unreachable, and the
   * nodes.h assertions in the 2026-08-02 campaign (301 artifacts) were all
   * this.  The bug is inherited verbatim from OSS-Fuzz's own postgresql
   * project -- see UPSTREAM.md.
   */
  parsetree_list = raw_parser(query_string, RAW_PARSE_DEFAULT);
  MemoryContextSwitchTo(oldcontext);

  foreach (parsetree_item, parsetree_list) {
    RawStmt *parsetree = lfirst_node(RawStmt, parsetree_item);
    MemoryContext per_parsetree_context = NULL;
    List *querytree_list;
    List *plantree_list;
    Portal portal;
    DestReceiver *receiver;
    int16 format;
    bool snapshot_set = false;

    if (lnext(parsetree_list, parsetree_item) != NULL) {
      per_parsetree_context =
          AllocSetContextCreate(MessageContext, "per-parsetree message context", ALLOCSET_DEFAULT_SIZES);
      oldcontext = MemoryContextSwitchTo(per_parsetree_context);
    } else {
      oldcontext = MemoryContextSwitchTo(MessageContext);
    }

    /*
     * A snapshot per statement, exactly as the backend's own
     * exec_simple_query() does it.
     *
     * pg_plan_query() opens with "Planner must have a snapshot in case it
     * calls user-defined functions", followed by Assert(ActiveSnapshotSet()),
     * and this loop had no snapshot handling at all, so EVERY statement that
     * reached the planner tripped it.  `SELECT 1;` was enough.  Utility
     * statements were unaffected -- pg_plan_queries() skips planning for them
     * -- which is why `VACUUM;` and `BEGIN; VACUUM;` looked clean and sent the
     * diagnosis chasing VACUUM and transaction blocks for hours.  The rule was
     * always just "anything that gets planned".
     *
     * analyze_requires_snapshot() is the same gate the backend uses: utility
     * statements do not need one, and pushing a snapshot for them would differ
     * from upstream behaviour for no benefit.
     *
     * Note this is OUR exec_simple_query(), a local reimplementation -- the
     * backend's is static to tcop/postgres.c and cannot be called.  Every
     * responsibility that function has is therefore ours to discharge, and
     * this one had been missing since the target started executing SQL at all
     * (0395d27, 2026-08-05).  Upstream OSS-Fuzz's older harness had it and a
     * 2025 "fix" deleted it along with the backend bring-up, which was safe
     * only because that target no longer runs anything.
     */
    if (analyze_requires_snapshot(parsetree)) {
      PushActiveSnapshot(GetTransactionSnapshot());
      snapshot_set = true;
    }

    querytree_list = pg_analyze_and_rewrite_fixedparams(parsetree, query_string, NULL, 0, NULL);
    plantree_list = pg_plan_queries(querytree_list, query_string, CURSOR_OPT_PARALLEL_OK, NULL);

    if (snapshot_set)
      PopActiveSnapshot();

    CHECK_FOR_INTERRUPTS();

    /*
     * RUN the plan.  Everything above this point was already here; the
     * function stopped at pg_plan_queries() and discarded its result -- the
     * return value was not even assigned.
     *
     * So the target parsed, analysed, rewrote and planned, and never executed
     * anything, while being named simple_query_fuzzer and calling a function
     * named exec_simple_query.  Measured on 2026-08-24:
     *
     *   SELECT count(*) FROM generate_series(1,20000000)     8 ms
     *   CREATE TEMP TABLE .. AS SELECT count(*) FROM ..      5 ms
     *
     * against spi_query_fuzzer, which ran both past a 100-second timeout.  The
     * CTAS is the one that settles it: it returns no rows to a client, so a
     * missing client connection cannot explain the result.  And no ERROR was
     * raised for either -- planning them genuinely succeeds.  See
     * FINDINGS/simple-query-executes-no-sql.
     *
     * This mirrors tcop/postgres.c's exec_simple_query() from the same point,
     * minus the FetchStmt binary-format lookup, which needs a cursor this
     * target never creates.
     *
     * DestNone, not DestDebug or DestRemote: there is no client socket, and
     * the tuples are not the point -- reaching the executor at all is.
     */
    /*
     * Do not EXECUTE transaction-control statements.
     *
     * This harness calls StartTransactionCommand() directly rather than going
     * round PostgresMain's loop, so the transaction BLOCK state (TBLOCK_*) is
     * never what those statements expect. ROLLBACK reaches
     * UserAbortTransactionBlock, falls through to its default branch and calls
     * elog(FATAL, "unexpected state"), and FATAL means proc_exit() -- the
     * process dies, libFuzzer reports "fuzz target exited", and the run is
     * over.
     *
     * Measured 2026-08-24, the day this function learned to execute at all:
     * the target managed 86 executions of a 227-input seed corpus before
     * dying, every run, with the corpus never growing. Utility statements skip
     * planning, so before execution existed this was simply unreachable.
     *
     * They are still parsed, analysed and planned above -- that is where the
     * interesting surface is for a statement whose execution we cannot honour.
     * Declared in the deviation line as "no-xact-control".
     */
    if (IsA(parsetree->stmt, TransactionStmt)) {
      if (snapshot_set)
        ; /* already popped above */
      MemoryContextSwitchTo(oldcontext);
      if (per_parsetree_context)
        MemoryContextDelete(per_parsetree_context);
      continue;
    }

    portal = CreatePortal("", true, true);
    portal->visible = false;

    PortalDefineQuery(portal, NULL, query_string,
                      CreateCommandTag(parsetree->stmt), plantree_list, NULL);
    PortalStart(portal, NULL, 0, InvalidSnapshot);

    format = 0;                 /* TEXT */
    PortalSetResultFormat(portal, 1, &format);

    receiver = CreateDestReceiver(DestNone);
    MemoryContextSwitchTo(oldcontext);
    /*
     * PG18 dropped the run_once parameter from PortalRun. Guarded rather than
     * pinned: this harness builds against 16, 17, 18 and master at once, and
     * the -head workspaces track moving branches, so an upstream signature
     * change arrives without warning. It arrived on 2026-08-29 and failed every
     * PG18 build in the next campaign.
     */
#if PG_VERSION_NUM >= 180000
    (void) PortalRun(portal, FETCH_ALL,
                     true,      /* always top level */
                     receiver, receiver, NULL);
#else
    (void) PortalRun(portal, FETCH_ALL,
                     true,      /* always top level */
                     true,      /* run_once, ignored here */
                     receiver, receiver, NULL);
#endif
    receiver->rDestroy(receiver);
    PortalDrop(portal, false);

    /*
     * Switch out before deleting. This deleted per_parsetree_context while it
     * was still CurrentMemoryContext, which mcxt.c asserts against
     * (Assert(context != CurrentMemoryContext), mcxt.c:502) and which leaves
     * CurrentMemoryContext dangling in a release build.
     *
     * Only reachable for multi-statement input, and only now that the
     * analyzer runs at all -- with RAW_PARSE_TYPE_NAME the target died in
     * castNode() long before here, so this sat unreachable behind that bug
     * the way the others did. Inherited from OSS-Fuzz's postgresql project.
     */
    MemoryContextSwitchTo(oldcontext);
    if (per_parsetree_context)
      MemoryContextDelete(per_parsetree_context);
  }

  /* The caller frees query_string; do not leave elog.c pointing at it. */
  debug_query_string = NULL;
}

/* provided by fuzzer_initialize.c */
#include "fuzz_canary.h"
#include "fuzz_probe.h"
#include "fuzz_timeout.h"
#include "fuzz_lineage.h"

extern int FuzzerInitialize(char *dbname, char ***argv);

/* postgres.c, exported by add_fuzzers.diff: clears its static xact_started */
extern void pgfuzz_reset_xact_started(void);

/*
 * This is a BACKEND harness, not a standalone one, and it has to be.
 *
 * pg_analyze_and_rewrite_fixedparams() and pg_plan_queries() resolve every
 * name they see through the catalog, so without a live backend they reach
 * SearchCatCacheInternal with no relcache and no shared memory and simply
 * hang -- measured: `SELECT 1;` never returns.
 *
 * It survived as a standalone target only because it parsed with
 * RAW_PARSE_TYPE_NAME and died in castNode() before the analyzer, i.e. the
 * two defects concealed each other.  Fixing the parse mode alone turns a
 * target that did nothing into a target that hangs, so both have to change
 * together.
 */
int LLVMFuzzerInitialize(int *argc, char ***argv) {
  FuzzerInitialize("simple_query_db", argv);
  pgfuzz_canary_init();

  /*
   * FuzzerInitialize() has already done MemoryContextInit(),
   * pg_initialize_timing() (PG19+), InitializeGUCOptions(),
   * InitializeMaxBackends(), the full shared-memory and InitPostgres
   * sequence, and MessageContext -- so none of that is repeated here.
   */

  /*
   * set_stack_base() deliberately does NOT go here. libFuzzer calls this
   * function at a different call depth than it calls LLVMFuzzerTestOneInput,
   * so a base recorded here is offset from the stack the inputs actually run
   * on -- see the call in LLVMFuzzerTestOneInput.
   */
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  /*
   * Take SIGALRM back from libFuzzer, once, HERE and not in
   * LLVMFuzzerInitialize -- libFuzzer installs its handler after
   * initialization returns, so reclaiming any earlier is the bug.
   * fuzz_timeout.h named this target as one of three with nothing bounding a
   * single input, and was then included by exactly one of them.
   */
  pgfuzz_timeout_reclaim();

  /*
   * Does a FATAL from this target carry any text?
   *
   * add_fuzzers.diff's elog.c hunk #ifdefs out EmitErrorReport() to silence
   * routine rejections, and errfinish() reaches that call only for NON-ERROR
   * levels -- so it silences FATAL and PANIC too. That is process-wide, not
   * per-target, which is exactly why the canary belongs in every target that
   * can crash and not only in the one where it was first written.
   */
  pgfuzz_probe_fatal_canary();

  if (size == 0)
    return 0;

  sigjmp_buf local_sigjmp_buf;
  char *query_string = (char *) calloc(size + 1, sizeof(char));
  memcpy(query_string, data, size);

  /*
   * This block is PostgresMain's error-recovery path and must run on the
   * *longjmp* return, not the normal one -- compare postgres.c, which is
   * `if (sigsetjmp(local_sigjmp_buf, 1) != 0)`.  The test used to be
   * inverted: recovery ran on entry and the error path ran nothing.
   *
   * Two things followed.  EmitErrorReport() was called before any error had
   * been raised, and its first statement is
   * `edata = &errordata[errordata_stack_depth]` with the empty stack encoded
   * as -1 -- so every process formed errordata[-1] on its first unit, which
   * is the 552-hit UBSan family from the 2026-08-02 campaign.  (No memory is
   * read: CHECK_STACK_DEPTH is a plain if, present in release builds, and it
   * throws on the next line.  UBSan flags the subscript expression itself.)
   * And because FlushErrorState() never ran on the error path, a unit that
   * raised ERROR left the stack dirty, so the following unit reported the
   * previous unit's error and was itself skipped -- roughly every other
   * input was silently discarded.
   *
   * The body goes in the zero-return arm and the recovery in the other, with
   * NO fall-through between them.  PostgresMain can put recovery first and
   * fall through because its sigsetjmp sits outside `for (;;) { ReadCommand
   * ... }`, so after an error it goes on to the *next* command.  A fuzz
   * harness has one input per call, so falling through re-runs the same
   * input -- which raises the same ERROR, longjmps back, recovers, falls
   * through again, forever.
   *
   * That was a real hang, not a hypothetical: `SELECT 1;` spun at 100% CPU
   * until killed, and the process was State: R the whole time, which is what
   * distinguished it from the lock-wait it looked like.  The original
   * inverted test accidentally avoided it -- on longjmp its condition was
   * false, so nothing ran and the call returned.
   *
   * savemask 1, as in postgres.c: the signal mask must be restored, or an
   * error raised inside a handler leaves signals blocked.
   */
  if (sigsetjmp(local_sigjmp_buf, 1) == 0) {
    PG_exception_stack = &local_sigjmp_buf;
    error_context_stack = NULL;

    /*
     * Per iteration, not once in LLVMFuzzerInitialize.  libFuzzer calls
     * LLVMFuzzerInitialize at a different call depth than it calls
     * LLVMFuzzerTestOneInput, so a base recorded there is offset from the
     * stack every input actually runs on, and check_stack_depth() then reads
     * that constant offset as enormous depth and throws "stack depth limit
     * exceeded" on trivial SQL.  Hoisting this out of the loop as an
     * "optimisation" is what raised the ERROR that the fall-through above
     * then looped on.
     */
    set_stack_base();

    MemoryContextSwitchTo(MessageContext);
    MemoryContextReset(MessageContext);
    SetCurrentStatementStartTimestamp();

    /*
     * A transaction per input.  REQUIRED -- not a workaround.
     *
     * PostgresMain does not wrap its call because the backend's
     * exec_simple_query() runs start_xact_command() itself, per statement
     * (postgres.c:1046 and :1143).  OURS is a local reimplementation with no
     * such call, so without this nothing starts a transaction at all: parse
     * analysis reaches the catcache outside one and trips
     * Assert(IsTransactionState()) at relcache.c:2073, and
     * GetTransactionSnapshot() above has no transaction to take a snapshot in.
     *
     * That is exactly what removing it measured on 2026-08-15.  It was read at
     * the time as evidence about stale xact_started bookkeeping; it was not.
     * Every responsibility the backend's function has is this one's to
     * discharge, and supplying the transaction is one of them.
     */
    StartTransactionCommand();
    pgfuzz_timeout_arm();
    exec_simple_query(query_string);
    pgfuzz_timeout_disarm();
    CommitTransactionCommand();
  } else {
    error_context_stack = NULL;
    HOLD_INTERRUPTS();    pgfuzz_probe_show_error("simple_query_fuzzer");


    disable_all_timeouts(false);
    QueryCancelPending = false;
    pq_comm_reset();

    /*
     * PostgresMain calls EmitErrorReport() here unconditionally
     * (postgres.c:4485), and mirroring it is why this line exists.  It is
     * gated anyway, because the cost is not symmetric: a real backend reports
     * an error to a waiting client a few times a second, while a fuzz target
     * rejects the overwhelming majority of its inputs and would emit one line
     * per rejection.
     *
     * Measured, not assumed. This call was a silent no-op for as long as it
     * existed, because fuzzer_initialize.c zeroed Log_destination. Restoring
     * that destination -- so FATAL and PANIC would stop vanishing -- made this
     * line start writing, and simple_query_fuzzer fell from 88,634 executions
     * per round to 192 on 11 workspaces at once. The starvation gate caught it
     * in round 1, which is precisely the job it was added for.
     *
     * FATAL and PANIC still print without this: errfinish() emits them
     * directly now that the add_fuzzers.diff hunk is narrowed to
     * elevel >= FATAL. What is gated here is the per-input ERROR chatter, and
     * PGFUZZ_ECHO_ERRORS=1 turns it back on for triage, where seeing why an
     * input was rejected is worth more than throughput.
     */
    {
      static int echo = -1;

      if (echo < 0)
      {
        const char *v = getenv("PGFUZZ_ECHO_ERRORS");

        echo = (v != NULL && v[0] == '1') ? 1 : 0;
      }
      if (echo)
        EmitErrorReport();

      /*
       * Nothing in the else branch on purpose. FlushErrorState() already runs
       * further down this same recovery block; calling it here as well would
       * flush an already-empty stack, and a first draft of this did exactly
       * that.
       */
    }

    /*
     * Cleared after the report is emitted and before the storage it points at
     * can be reused -- postgres.c:4448.  EmitErrorReport() above is what reads
     * it, to print the "STATEMENT:" line.
     */
    debug_query_string = NULL;

    /*
     * The failed statement left a transaction open and it has to be rolled
     * back, or the next input starts inside an aborted transaction and every
     * query after the first error fails with "current transaction is
     * aborted".
     */
    pgfuzz_timeout_disarm();
    AbortCurrentTransaction();

    /*
     * postgres.c:4458.  Drops any portal left pinned by a failed statement.
     *
     * This WAS a no-op, kept on the argument that it "becomes load-bearing the
     * moment this harness gains PortalRun()".  That moment is 2026-08-24: the
     * local exec_simple_query() now creates a portal per statement and runs it,
     * so a statement that raises mid-execution leaves one pinned and this call
     * is the thing that drops it.
     *
     * Worth noting as an argument that paid off -- the sequence was kept
     * complete when it cost nothing, and needed no archaeology when it started
     * to matter.
     */
    PortalErrorCleanup();

    /*
     * After the abort, not before -- postgres.c:4453 then :4473.  This was
     * running ahead of AbortCurrentTransaction(), which resets JIT state that
     * the abort may still touch.
     */
    jit_reset_after_error();

    /*
     * And tell postgres.c that no transaction command is open any more.
     *
     * This is the line PostgresMain has in its own sigsetjmp recovery block,
     * right after AbortCurrentTransaction() -- "We don't have a transaction
     * command open anymore", followed by "xact_started = false".
     *
     * NOTE: for THIS target the call is a no-op, and the comment below
     * describes a chain that cannot happen here.  xact_started is read only by
     * start_xact_command(), finish_xact_command() and enable_statement_timeout(),
     * all static to postgres.c -- and this harness calls none of them, because
     * it has its own exec_simple_query().  Kept because it is free, because it
     * matches PostgresMain, and because protocol_fuzzer DOES drive
     * PostgresMain.  It was mistaken for the cause of the snapshot assert on
     * 2026-08-15; it was not.
     *
     * xact_started is file-static to postgres.c, so a harness cannot assign it
     * directly; add_fuzzers.diff exports pgfuzz_reset_xact_started() for
     * exactly this.  Skipping it left the flag true with no transaction open,
     * and the NEXT input's start_xact_command() then concluded a transaction
     * was already running and started none -- so parse analysis reached the
     * catcache outside a transaction and tripped Assert(IsTransactionState())
     * in relcache.c.  Every error is followed by the next input, so this was
     * one bad input away from mattering, permanently.
     */
    pgfuzz_reset_xact_started();

    /*
     * MessageContext, not TopMemoryContext -- postgres.c:4479.
     *
     * TopMemoryContext is never reset for the life of the process, so anything
     * allocated between here and the next input's MemoryContextReset() stays
     * allocated forever.  Most fuzz inputs are malformed and therefore take
     * THIS path, so the harness was leaking on the majority of its iterations.
     * MessageContext is reset at the top of every input, which is exactly why
     * PostgresMain returns to it.
     */
    MemoryContextSwitchTo(MessageContext);
    FlushErrorState();

    RESUME_INTERRUPTS();
  }

  /*
   * Do not leave PG_exception_stack pointing into this frame once we return:
   * anything that ereports between iterations would longjmp into a dead
   * stack.
   */
  PG_exception_stack = NULL;
  free(query_string);

  /* See fuzz_canary.h: reachable-but-growing state is invisible to LSan. */
  pgfuzz_canary_check(data, size);
  return 0;
}

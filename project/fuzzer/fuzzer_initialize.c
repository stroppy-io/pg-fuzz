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
#include "optimizer/optimizer.h"
#include "parser/analyze.h"
#include "parser/parser.h"
#include "postmaster/interrupt.h"
#if PG_VERSION_NUM >= 180000
/*
 * InitPostmasterChildSlots(). The implementation lives in pmchild.c, new in
 * PG18, but the declaration is in postmaster.h -- there is no pmchild.h.
 */
#include "postmaster/postmaster.h"
#endif
#include "storage/ipc.h"
#include "storage/procsignal.h"
#if PG_VERSION_NUM >= 190000
/* ShmemCallRequestCallbacks() */
#include "storage/shmem_internal.h"
#endif
#include "storage/proc.h"
#include "tcop/tcopprot.h"
#include "utils/datetime.h"
#include "utils/guc.h"          /* SetConfigOption() */
#include "utils/memutils.h"
#include "utils/portal.h"
#include "utils/snapmgr.h"
#include "utils/timeout.h"
/* pg_initialize_timing(); PostgreSQL 19 and later */
#include "portability/instr_time.h"

#include <libgen.h>

#include "fuzz_lsan.h"
#include "fuzz_logspam.h"
#include <unistd.h>

extern const char *progname;

/* $OUT, captured before ChangeToDataDir(); see FuzzerInitialize. */
char pgfuzz_out_dir[MAXPGPATH];
static MemoryContext row_description_context = NULL;
static StringInfoData row_description_buf;
static const char *username = "username";

int FuzzerInitialize(char *dbname, char ***argv){
  char *av[5];
  char arg_path[128];
  char path_to_db[128];
  char untar[512];
  char *exe_path = (*argv)[0];
  //dirname() can modify its argument
  char *exe_path_copy = strdup(exe_path);
  char *dir = dirname(exe_path_copy);

  /*
   * Everything below is one-time backend startup whose allocations are
   * meant to outlive every input. LSan judges them at exit and libFuzzer
   * turns the report into a crash on the empty input. See fuzz_lsan.h.
   */
  PGFUZZ_LSAN_INIT_BEGIN();
  chdir(dir);
  /*
   * Remember it: ChangeToDataDir() below moves the CWD into the data
   * directory, so by the time a harness runs, a relative path no longer
   * reaches $OUT. backend_types_fuzzer read "extra_types.txt" relative and
   * silently got nothing -- the configured types were never loaded, and the
   * failure was invisible because a missing file is indistinguishable from
   * "none configured".
   */
  strlcpy(pgfuzz_out_dir, dir, sizeof(pgfuzz_out_dir));
  free(exe_path_copy);

  /*
   * The data directory is per *process*, not per target.
   *
   * It used to be /tmp/<dbname>, fixed. libFuzzer's -jobs/-workers mode runs
   * several processes of the same target at once, and every one of them
   * executes the rm -rf/mkdir/cp below -- on the same path. So each new
   * worker deleted the data directory the others were running against, and
   * they all took CreateDataDirLockFile() in the same place. Campaigns have
   * been running these targets with JOBS=4 and sweeps with 8.
   *
   * The visible symptoms were all downstream of that: workers exiting 1 for
   * no stated reason, and libFuzzer's per-job fuzz-N.log files disappearing
   * entirely -- ChangeToDataDir() below leaves the process CWD inside the data
   * directory, so once another worker unlinked it the logs were being written
   * into a deleted directory. /proc/1/cwd read "/tmp/spi_query_db/data
   * (deleted)", which is what finally gave this away.
   */
  snprintf(arg_path, sizeof(arg_path), "/tmp/%s-%d/data", dbname, (int) getpid());
  snprintf(path_to_db, sizeof(path_to_db), "-D\"/tmp/%s-%d/data\"", dbname, (int) getpid());
  snprintf(untar, sizeof(untar),
           "rm -rf /tmp/%s-%d; mkdir /tmp/%s-%d; cp -r data /tmp/%s-%d",
           dbname, (int) getpid(), dbname, (int) getpid(), dbname, (int) getpid());

  av[0] = "tmp_install/usr/local/pgsql/bin/postgres";
  av[1] = path_to_db;
  av[2] = "-F";
  av[3] = "-k\"/tmp\"";
  av[4] = NULL;

  system(untar);

  /*
   * main() is the ONLY place in the backend that assigns MyProcPid (the other
   * is fork_process.c, for postmaster children) -- and main.diff #ifdefs main()
   * out so the backend can be linked as a library.  So every fuzz target ran
   * with MyProcPid == 0, SharedInvalBackendInit() registered the backend with
   * procPid = 0, and SIResetAll() at the end of StartupXLOG asserted on it.
   *
   * Without --enable-cassert that assertion is compiled out and the backend
   * limps on with a bogus pid, which is why this survived unnoticed -- here and
   * in the upstream OSS-Fuzz integration this harness came from.
   *
   * Do what main() would have done, in main()'s order.
   */
  MyProcPid = getpid();
  progname = get_progname(av[0]);
  MemoryContextInit();

  InitStandaloneProcess(av[0]);
  SetProcessingMode(InitProcessing);

  /*
   * PostgreSQL 19 added a timing subsystem that InitializeGUCOptions()
   * depends on: applying the compiled-in default for timing_clock_source runs
   * check_timing_clock_source(), which does Assert(timing_initialized) on a
   * non-EXEC_BACKEND build.  PostmasterMain() and InitProcessGlobals() call
   * pg_initialize_timing() before GUC setup; this sequence does not go
   * through either, so the call has to be made here.
   */
#if PG_VERSION_NUM >= 190000
  pg_initialize_timing();
#endif

  InitializeGUCOptions();
  process_postgres_switches(4, av, PGC_POSTMASTER, NULL);

  SelectConfigFiles(arg_path, progname);

  checkDataDir();
  ChangeToDataDir();
  CreateDataDirLockFile(false);
  LocalProcessControlFile(false);

  /*
   * Everything from here mirrors PostgresSingleUserMain() and then the top of
   * PostgresMain(), in their exact order.  It has to: this harness previously
   * hand-rolled an approximation, which "worked" only because assertions were
   * compiled out.  With --enable-cassert it tripped all_timeouts_initialized
   * and then SIResetAll's Assert(stateP->procPid != 0) -- the backend was
   * never correctly initialised, and every result it produced was suspect.
   */
  /*
   * PostgreSQL 19 moved the shared-memory sizing of every core subsystem
   * behind a callback registry, and PostgresSingleUserMain() registers them
   * here -- after LocalProcessControlFile(), before
   * process_shared_preload_libraries().
   *
   * Skipping it does not fail here; it fails much later and looks unrelated.
   * Nothing sizes or creates the PGPROC array, so CreateSharedMemoryAndSemaphores()
   * completes "successfully" with no proc header, and InitProcess() below dies
   * on
   *
   *     elog(PANIC, "proc header uninitialized")      proc.c:401
   *
   * which is where the backtrace points and where the cause is not.
   *
   * This is the same defect as the missing InitPostmasterChildSlots() one
   * version earlier, and found the same way: the smoke gate rejected the build
   * instead of shipping a workspace whose backend targets silently do nothing.
   * pg19-head and pgmaster failed their smoke test on spi_query_fuzzer while
   * pg18-head passed, which is exactly the split this call explains.
   */
#if PG_VERSION_NUM >= 190000
  RegisterBuiltinShmemCallbacks();
#endif

  process_shared_preload_libraries();
  InitializeMaxBackends();

  /*
   * PostgreSQL 18 added InitializeFastPathLocks() and 19 added the shmem
   * callback API, and PostgresSingleUserMain() calls both here.  Skipping
   * ShmemCallRequestCallbacks() is not cosmetic: it is the transition into
   * SRS_REQUESTING, and without it shmem_request_state is still SRS_INITIAL
   * when CreateSharedMemoryAndSemaphores() reaches
   * Assert(shmem_request_state == SRS_REQUESTING) in InitShmemAllocator().
   *
   * That is why spi_query_fuzzer and backend_types_fuzzer died at startup on
   * pg19-head and pgmaster specifically -- a different failure from the
   * MyBackendType and flinfo bugs that stopped them on 16..18, and one that
   * only appears once those are fixed.
   */
  /*
   * PostgreSQL 18 moved postmaster child-slot accounting into pmchild.c, and
   * PostgresSingleUserMain() calls InitPostmasterChildSlots() here -- between
   * InitializeMaxBackends() and InitializeFastPathLocks(), which is why this
   * call goes in that exact position.
   *
   * Skipping it is not survivable and not quiet in the way the other omissions
   * were.  num_pmchild_slots stays 0, and InitializeShmemGUCs() below reaches
   * MaxLivePostmasterChildren() through CalculateShmemSize() ->
   * PMSignalShmemSize(), which does:
   *
   *     if (num_pmchild_slots == 0)
   *         elog(ERROR, "PM child array not initialized yet");
   *
   * That ERROR arrives before any error output is configured, so errfinish()
   * goes straight to proc_exit() and the process exits 1 having printed
   * nothing at all -- not even libFuzzer's banner, because libFuzzer calls
   * LLVMFuzzerInitialize() before it prints anything.  From the outside the
   * campaign looks healthy: containers start, run logs are created, and every
   * backend-starting target silently contributes zero coverage.
   *
   * This is what killed backend_types, extension_funcs, simple_query and
   * spi_query on EVERY PostgreSQL 18+ workspace -- oriole18, pg18-4, pg18-head,
   * pg19, pg19-head and pgmaster alike.  It was read as an OrioleDB problem for
   * days because OrioleDB 18 was where it was noticed.
   */
#if PG_VERSION_NUM >= 180000
  InitPostmasterChildSlots();
  InitializeFastPathLocks();
#endif

  process_shmem_requests();

#if PG_VERSION_NUM >= 190000
  ShmemCallRequestCallbacks();
#endif

  InitializeShmemGUCs();
  InitializeWalConsistencyChecking();
  CreateSharedMemoryAndSemaphores();

  /* PostgresSingleUserMain sets this *before* InitProcess, not after. */
  PgStartTime = GetCurrentTimestamp();
  InitProcess();

  /* --- from here, the top of PostgresMain() --- */

  /*
   * The signal handlers are not optional.  procsignal_sigusr1_handler in
   * particular is what services shared-invalidation and recovery-conflict
   * signalling, which is the machinery whose state SIResetAll asserts over.
   */
  pqsignal(SIGHUP, SignalHandlerForConfigReload);
  pqsignal(SIGINT, StatementCancelHandler);
  pqsignal(SIGTERM, die);
  pqsignal(SIGQUIT, die);
  InitializeTimeouts();               /* establishes the SIGALRM handler */
  pqsignal(SIGPIPE, SIG_IGN);
  pqsignal(SIGUSR1, procsignal_sigusr1_handler);
  pqsignal(SIGUSR2, SIG_IGN);
  pqsignal(SIGFPE, FloatExceptionHandler);
  pqsignal(SIGCHLD, SIG_DFL);

  BaseInit();
  sigprocmask(SIG_SETMASK, &UnBlockSig, NULL);

  /*
   * INIT_PG_LOAD_SESSION_LIBS, as PostgresMain passes for a non-walsender.
   * It also makes InitPostgres itself run process_session_preload_libraries()
   * at the right point, so the harness must not call that separately.
   */
#if PG_VERSION_NUM >= 170000
  InitPostgres("dbfuzz", InvalidOid, username, InvalidOid,
               INIT_PG_LOAD_SESSION_LIBS, NULL);
#else
  InitPostgres("dbfuzz", InvalidOid, username, InvalidOid, true, false, NULL);
#endif

  SetProcessingMode(NormalProcessing);

  /*
   * InitStandaloneProcess() leaves MyBackendType == B_STANDALONE_BACKEND, and
   * pgstat_tracks_io_op() lists that type in no_temp_rel: any IO on a
   * temporary relation then fails Assert(pgstat_tracks_io_op(...)) in
   * pgstat_io.c.  The seed corpora come from the regression tests, which
   * create temp tables constantly, so spi_query_fuzzer died during corpus
   * load and executed *zero* units in all 24 workspaces of the 2026-08-02
   * campaign -- while its reproducer count kept climbing, which is what hid
   * it for six campaigns.
   *
   * B_BACKEND is the honest description of what this process does: it runs
   * client queries.  It reached single-user main only because that is the
   * only way to boot a backend without a postmaster.  B_BACKEND is absent
   * from no_temp_rel on every branch from 16 to master.
   *
   * The underlying assertion is a real PostgreSQL issue -- single-user mode
   * cannot do temp-relation IO under --enable-cassert -- and is written up
   * separately for pgsql-hackers.  It is assert-only and unreachable in
   * production, so masking it here loses nothing and unblocks the target.
   */
  MyBackendType = B_BACKEND;

  /*
   * Bound what a single fuzz input can consume.
   *
   * libFuzzer's -timeout is useless here: InitializeTimeouts() above installs
   * PostgreSQL's SIGALRM handler, and libFuzzer's per-unit watchdog is built
   * on that same signal. So the moment this harness boots a backend, nothing
   * stops a runaway query. Measured: spi_query_fuzzer reported
   * slowest_unit_time_sec = 3089 -- one input ran 51 minutes under a nominal
   * 25-second timeout, and a single mutated INSERT ... SELECT grew its data
   * directory to 150 GB before the disk was nearly full. -rss_limit_mb caps
   * memory, not disk.
   *
   * The fix uses PostgreSQL's own timeout machinery, which works precisely
   * because it owns the signal. statement_timeout aborts the query the way any
   * ordinary slow statement would; temp_file_limit and the disabled disk-heavy
   * plan types keep a single statement from writing the filesystem full before
   * the timeout can fire.
   *
   * PGC_S_OVERRIDE so an input cannot SET them back -- the corpus is
   * PostgreSQL's regression suite, which sets GUCs constantly.
   */
  /*
   * Throttle repetitive server log messages before the first query runs.
   *
   * A protocol target gets the same complaint back for nearly every input --
   * desync is the expected result of feeding garbage to a wire protocol --
   * and that one message was half of a slice log. See fuzz_logspam.h for why
   * this is emit_log_hook and not log_min_messages.
   */
  pgfuzz_logspam_install();

  SetConfigOption("statement_timeout", "10s", PGC_SUSET, PGC_S_OVERRIDE);
  SetConfigOption("temp_file_limit", "1GB", PGC_SUSET, PGC_S_OVERRIDE);
  SetConfigOption("idle_in_transaction_session_timeout", "10s",
                  PGC_SUSET, PGC_S_OVERRIDE);

  BeginReportingGUCOptions();

  MessageContext = AllocSetContextCreate(TopMemoryContext,
					 "MessageContext",
					 ALLOCSET_DEFAULT_SIZES);
  row_description_context = AllocSetContextCreate(TopMemoryContext,
						  "RowDescriptionContext",
						  ALLOCSET_DEFAULT_SIZES);
  MemoryContextSwitchTo(row_description_context);
  initStringInfo(&row_description_buf);
  MemoryContextSwitchTo(TopMemoryContext);

  whereToSendOutput = DestNone;

  /*
   * Log_destination keeps LOG_DESTINATION_STDERR, deliberately.
   *
   * It used to be zeroed, which looks harmless next to whereToSendOutput =
   * DestNone -- both say "no client to talk to". But send_message_to_server_log
   * gates on (Log_destination & LOG_DESTINATION_STDERR), so zeroing it silences
   * the SERVER LOG as well, and every FATAL and PANIC then reached libFuzzer
   * with no message and no statement attached. Triage started from a bare
   * stack.
   *
   * Volume is not a concern: errfinish() only reaches EmitErrorReport() for
   * non-ERROR levels, and add_fuzzers.diff now suppresses those below FATAL in
   * fuzzing builds. So what survives to stderr is exactly the FATAL/PANIC text
   * we want and nothing else.
   *
   * Measured: with the elog.c hunk narrowed but this line still zeroing the
   * destination, a deliberate FATAL still printed nothing -- the fix was half
   * a fix, and scripts/probe-harness.sh --fatal is what said so.
   */
  Log_destination = LOG_DESTINATION_STDERR;

  /*
   * Drop the proc_exit/shmem_exit callbacks that InitProcess() and friends
   * just registered.  A fuzz target is a disposable process working on a
   * private copy of the data directory under /tmp, so there is nothing worth
   * tearing down -- and running the teardown is actively harmful: libFuzzer
   * exits via exit(), which walks those callbacks into ProcKill(), which
   * PANICs and gets reported as a crash on *every* run, including runs where
   * the input was processed cleanly.
   *
   * This matters more now that the startup sequence above creates real shared
   * memory (it must, so that a preloaded extension's shmem_startup_hook runs);
   * before that there was no PGPROC to kill and the exit path was silent.
   */
  on_exit_reset();

  PGFUZZ_LSAN_INIT_END();

  return 0;
}

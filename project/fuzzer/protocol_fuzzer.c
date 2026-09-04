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
#include "common/ip.h"
#include "common/username.h"
#include "executor/spi.h"
#include "jit/jit.h"
#include "libpq/auth.h"
#include "libpq/libpq.h"
#include "libpq/pqsignal.h"
#include "miscadmin.h"
#include "optimizer/optimizer.h"
#include "parser/analyze.h"
#include "parser/parser.h"
#include "storage/bufmgr.h"
#include "storage/lock.h"
#include "storage/lwlock.h"
#include "storage/proc.h"
#include "tcop/tcopprot.h"
#include "utils/datetime.h"
#include "utils/memutils.h"
#include "utils/memdebug.h"
#include "utils/pidfile.h"
#include "utils/portal.h"
#include "utils/snapmgr.h"
#include "utils/ps_status.h"
#include "utils/timeout.h"

#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <libgen.h>

#include "fuzz_probe.h"
#include "fuzz_lsan.h"
#include "fuzz_deadline.h"
#include "fuzz_logspam.h"
#include "fuzz_lineage.h"

static sigjmp_buf postgre_exit;
static bool postgre_started;
static char *buffer;
static size_t buffersize;
static char *bufferpointer;
static char *av[6];

/*
 * pq_endmsgread() asserts PqCommReadingMsg, and PostgresSingleUserMain() can
 * return -- through our wrapped exit() -- either mid-message or not, so
 * calling it unconditionally aborts the backend on whichever inputs happen to
 * leave no read in progress.  That is 84 of run 4's "reproducers": all this
 * harness, none of them the protocol code.
 *
 * PqCommReadingMsg is static inside pqcomm.c, so the state has to be tracked
 * here.  pq_startmsgread() is wrapped for that and for nothing else.
 *
 * This block sits above LLVMFuzzerInitialize because that function calls
 * end_msgread_if_reading().  Defining it further down made the call an
 * implicit (non-static) declaration and the later static definition then
 * failed to compile: "static declaration follows non-static declaration".
 */
static bool reading_msg = false;

extern void __real_pq_startmsgread(void);

void __wrap_pq_startmsgread(void){
	reading_msg = true;
	__real_pq_startmsgread();
}

/* Only valid while a read is actually in progress. */
static void end_msgread_if_reading(void){
	if(reading_msg){
		reading_msg = false;
		pq_endmsgread();
	}
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
	pgfuzz_deadline_init();
	static char db_dir[128], db_arg[160], db_cmd[512];
	char *exe_path = (*argv)[0];
	//dirname() can modify its argument
	char *exe_path_copy = strdup(exe_path);
	char *dir = dirname(exe_path_copy);
	chdir(dir);
	free(exe_path_copy);
	
	/*
	 * Per-process data directory, as in fuzzer_initialize.c. It was
	 * /tmp/protocol_db, fixed, and libFuzzer's -jobs mode runs several
	 * processes of this target at once -- each executing the rm -rf below on
	 * the path the others are running against.
	 */
	snprintf(db_dir, sizeof(db_dir), "/tmp/protocol_db-%d", (int) getpid());
	snprintf(db_arg, sizeof(db_arg), "-D%s/data", db_dir);
	snprintf(db_cmd, sizeof(db_cmd),
			 "rm -rf %s; mkdir %s; cp -r data %s", db_dir, db_dir, db_dir);

	av[0] = "tmp_install/usr/local/pgsql/bin/postgres";
	av[1] = "--single";
	av[2] = db_arg;
	av[3] = "-F";
	av[4] = "dbfuzz";      /* trailing dbname: single-user mode's argv form */
	av[5] = NULL;
	/* av carries no dbname, so single-user mode falls back to the username;
	 * see the note in LLVMFuzzerTestOneInput. */

	system(db_cmd);
	/*
	 * tmp_install is copied once, to a fixed path, and only if it is not
	 * already there. It is a whole PostgreSQL install tree -- copying it per
	 * process put several GB into the container's writable layer for every
	 * worker, which is host disk, and this target runs with 8 of them.
	 *
	 * COPY TO A PRIVATE PATH AND RENAME, because the obvious form races:
	 *
	 *     test -d /tmp/tmp_install || cp -r tmp_install /tmp/
	 *
	 * Every worker starts at the same moment into a container whose /tmp is
	 * empty -- the container is fresh for each slice -- so all of them see the
	 * directory missing and all of them start copying a multi-gigabyte tree
	 * onto the same path. Whoever runs `postgres --single` while another
	 * worker is still writing gets a half-copied install and exits 1, with the
	 * cause discarded: libFuzzer removes the worker log without printing it,
	 * so the slice's whole record is "Job 0 exited with exit code 1".
	 *
	 * That is where an intermittently red sweep item came from -- REL_19 in
	 * run 33919705797, after two runs where the same target managed 611,969
	 * and 763,192 executions. The race is won almost every time, which is what
	 * made it look like infrastructure noise.
	 *
	 * rename(2) is atomic, so exactly one worker publishes the tree and the
	 * losers delete their copy and use the winner's. mv -T refuses to descend
	 * into an existing directory, which is what makes "somebody beat me" a
	 * clean failure rather than a merge.
	 */
	system("test -d /tmp/tmp_install || { "
		   "rm -rf /tmp/tmp_install.$$ && "
		   "cp -r tmp_install /tmp/tmp_install.$$ && "
		   "mv -T /tmp/tmp_install.$$ /tmp/tmp_install 2>/dev/null || "
		   "rm -rf /tmp/tmp_install.$$; }");

	/*
	 * main() is the only place that sets MyProcPid, and main.diff removes it --
	 * see fuzzer_initialize.c.  Without this the backend registers itself with
	 * procPid = 0 and SIResetAll() asserts at the end of StartupXLOG.
	 */
	MyProcPid = getpid();
	MemoryContextInit();
	/*
	 * PostgresSingleUserMain() strdup()s the database name in
	 * process_postgres_switches() and never frees it -- correct for a
	 * backend that exits, and the source of EVERY init-rooted leak this
	 * project has recorded. The siglongjmp target is inside this window,
	 * so the enable below is still reached when __wrap_proc_exit unwinds
	 * us out of the backend. See fuzz_lsan.h.
	 */
	PGFUZZ_LSAN_INIT_BEGIN();
	if(!sigsetjmp(postgre_exit, 0)){
		postgre_started = true;
		PostgresSingleUserMain(5, av, "fuzzuser");
	}
	PGFUZZ_LSAN_INIT_END();

	/*
	 * Throttle repetitive server log messages.
	 *
	 * This harness has its own LLVMFuzzerInitialize and does NOT go through
	 * fuzzer_initialize.c, so installing the hook there missed the one target
	 * that needed it most: desync is the expected reply to nearly every input
	 * here, and that single FATAL was half of a 37 MB slice log. Checked with
	 * `strings <target> | grep 'PGFUZZ LOG:'` after building, because the hook
	 * being absent looks exactly like the hook being present and quiet.
	 */
	pgfuzz_logspam_install();
	end_msgread_if_reading();
	return 0;
}

/*
 * proc_exit, not just exit.
 *
 * proc_exit() runs proc_exit_prepare(), which walks the on_shmem_exit
 * callbacks -- among them ProcKill(), which sets MyProc = NULL -- and only
 * then calls exit(). Wrapping exit() therefore catches the backend *after* it
 * has already dismantled itself, so the next input reached
 * Assert(MyProc != NULL) in BaseInit(). That is why calling PostgresMain per
 * input was necessary but not sufficient.
 *
 * Longjmping from here skips the teardown entirely and leaves MyProc, the
 * latch wait set and the rest of the backend intact for the next input, which
 * is what "boot once, then drive the message loop" actually requires.
 * fuzzer_initialize.c achieves the same end differently, with on_exit_reset()
 * after startup; that is not available here because this harness only regains
 * control *through* the exit path.
 *
 * The trade-off is real: a session's transaction and locks are no longer
 * unwound between inputs, so inputs are not independent. For a protocol
 * fuzzer, driving one long-lived session is arguably the point.
 *
 * BUT LWLOCKS ARE NOT A TRADE-OFF, THEY ARE A DEADLOCK.
 *
 * A lost transaction costs independence between inputs. A lost LWLock costs
 * the process: the next input that wants the same lock waits on a lock THIS
 * PROCESS ALREADY HOLDS, forever. Verified by attaching to a wedged run:
 *
 *   ReadAndExecuteSeedCorpora -> RunOne -> LLVMFuzzerTestOneInput
 *     -> PostgresMain -> HandleFunctionRequest (fastpath)
 *       -> dbms_pipe_create_pipe -> ora_lock_shmem
 *         -> LWLockAcquire -> PGSemaphoreLock -> futex, forever
 *
 * Nothing could break it. LWLockAcquire never reaches
 * CHECK_FOR_INTERRUPTS, so the per-input deadline in fuzz_deadline.h fires
 * into a void. libFuzzer only tests its graceful-exit flag BETWEEN inputs, so
 * SIGTERM is deferred to a check the process never reaches -- `timeout 600`
 * sent its own TERM and the process outlived it by twelve minutes. SIGKILL is
 * the only thing that works, and a killed process prints no statistics, so
 * every gate saw an absence rather than a failure. That is how one target hid
 * for two months behind three different wrong diagnoses.
 *
 * So: release what deadlocks, keep what the longjmp exists to preserve.
 * LWLockReleaseAll() and UnlockBuffers() are void and non-throwing, safe from
 * any state. AbortOutOfAnyTransaction() is deliberately NOT called -- it can
 * itself raise, which from an exit path is a recursion this cannot afford, and
 * transaction carry-over is the documented intent above.
 *
 * __wrap_exit stays as a backstop for exit paths that do not go through
 * proc_exit.
 */
extern void __real_proc_exit(int code);

void __wrap_proc_exit(int code){
	if(postgre_started){
		/*
		 * Release the shared state proc_exit_prepare() would have released,
		 * and NOTHING ELSE.
		 *
		 * proc_exit_prepare() runs before_shmem_exit(ShutdownPostgres):
		 *
		 *     AbortOutOfAnyTransaction();
		 *     LockReleaseAll(USER_LOCKMETHOD, true);
		 *
		 * TRIED THAT, AND IT CRASHES THE NEXT INPUT:
		 *
		 *     TRAP: failed Assert("MemoryContextIsValid(context)")  mcxt.c
		 *       ExceptionalCondition <- MemoryContextAlloc
		 *       <- PushActiveSnapshotWithLevel <- HandleFunctionRequest
		 *
		 * AbortOutOfAnyTransaction() destroys TopTransactionContext, and this
		 * wrapper then jumps back into a backend that is supposed to keep
		 * serving. The next allocation comes from a context that no longer
		 * exists. Full teardown and "keep the backend alive across inputs" are
		 * mutually exclusive -- which is exactly what the rationale above was
		 * warning about, and worth leaving recorded so it is not retried.
		 *
		 * So: only the two NON-DESTRUCTIVE releases. Both are void, neither
		 * can raise, and neither touches a memory context. They give back
		 * shared-memory state without dismantling the session.
		 *
		 * This is NOT sufficient. protocol_fuzzer still wedges in
		 * ora_lock_shmem -> LWLockAcquire, and a gdb breakpoint conditional on
		 * num_held_lwlocks > 0 at entry to ora_lock_shmem NEVER FIRED -- so
		 * whatever the deadlocked process holds, it is not a lock leaked
		 * across ora_lock_shmem calls. The cause is still open. See
		 * FINDINGS/harness-leaks-lwlocks-into-the-next-input.
		 */
		LWLockReleaseAll();
		UnlockBuffers();
		siglongjmp(postgre_exit, 1);
	}
	__real_proc_exit(code);
}

void __wrap_exit(int status){
	if(postgre_started)
		siglongjmp(postgre_exit, 1);
	else
		__real_exit(status);
}

/*
 * Serve the message type byte from the fuzz input.
 *
 * This read buffer[0] every call: the walking pointer was incremented and
 * never dereferenced, so a 100-byte input was byte 0 repeated 100 times. It
 * went unnoticed because the target executed millions of inputs -- 2,905,390
 * at cov 380 -- and execution count cannot distinguish "read the input" from
 * "read the first byte of it a great many times".
 */
int __wrap_pq_getbyte(void){
	if(!buffersize) return EOF;
	unsigned char cur = *bufferpointer++;
	buffersize--;
	return cur;
}

/*
 * ...and serve the rest of the message from it too.
 *
 * Wrapping only pq_getbyte covered the type byte and nothing else. SocketBackend
 * reads the 4-byte length and the body through pq_getmessage(), which calls
 * pq_getbytes() (pqcomm.c:1211 and :1256) -- unwrapped, so it reached the real
 * pq_recvbuf(), whose first act is socket_set_nonblocking() and which therefore
 * threw "there is no client connection" because MyProcPort is NULL and this
 * harness builds no Port. Every input died there, having consumed one byte.
 *
 * Returning EOF without consuming on a short read is deliberate: it mirrors the
 * real function's contract (the caller must not assume s was filled) and keeps
 * the consumption probe honest -- bytes we never handed over are not bytes we
 * read.
 */
int __wrap_pq_getbytes(char *s, size_t len){
	if(buffersize < len) return EOF;
	memcpy(s, bufferpointer, len);
	bufferpointer += len;
	buffersize -= len;
	return 0;
}

/*
 * And the one that actually matters: pq_getmessage().
 *
 * Wrapping pq_getbytes() alone changed nothing, and the probe said so --
 * "consumed 1 of 15" after the rebuild. --wrap only redirects references the
 * LINKER resolves, and pq_getmessage() calls pq_getbytes() from inside
 * pqcomm.c, the same translation unit, so that call is bound at compile time
 * and never reaches the linker. pq_getbyte() is wrapped successfully only
 * because its caller, SocketBackend(), lives in postgres.c.
 *
 * pq_getmessage() is likewise called from postgres.c, so wrapping it works.
 * The pq_getbytes wrapper above is kept for any cross-object caller, but it is
 * not what serves the message.
 *
 * Contract, from pqcomm.c:1202-1270: read a 4-byte network-order length that
 * counts itself, reject anything below 4 or above maxlen, then read len-4
 * bytes of body into the StringInfo.
 */
int __wrap_pq_getmessage(StringInfo s, int maxlen){
	uint32 len;

	resetStringInfo(s);

	if(buffersize < 4) return EOF;
	memcpy(&len, bufferpointer, 4);
	bufferpointer += 4; buffersize -= 4;
	len = pg_ntoh32(len);

	if(len < 4 || len > (uint32) maxlen) return EOF;
	len -= 4;

	if(len > 0){
		if(buffersize < len) return EOF;
		enlargeStringInfo(s, (int) len);
		memcpy(s->data, bufferpointer, len);
		bufferpointer += len; buffersize -= len;
		s->len = (int) len;
		s->data[len] = '\0';
	}
	return 0;
}

/*
** Main entry point.  The fuzzer invokes this function with each
** fuzzed input.
*/
int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
	/*
	 * Per-iteration stack base for check_stack_depth(); see the long note in
	 * fuzz_util.h:pgfuzz_run().  PostgresMain() does not record one -- in
	 * PostgreSQL 17 the only callers of set_stack_base() are PostmasterMain()
	 * and InitStandaloneProcess(), neither of which is on this path.
	 */
	set_stack_base();


	pgfuzz_probe_leak_canary();
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

	buffersize = size;
	buffer = (char *) calloc(size, sizeof(char));
	bufferpointer = buffer;
	memcpy(buffer, data, size);

	/*
	 * PostgresMain, not PostgresSingleUserMain.
	 *
	 * This used to re-run PostgresSingleUserMain() for every input -- a
	 * complete backend startup per fuzz case. Backend startup is full of
	 * one-shot initialisers guarded by Assert(x == NULL), so under
	 * --enable-cassert the second input tripped Assert(LatchWaitSet == NULL)
	 * in latch.c and the target executed exactly one unit, in every campaign
	 * it has ever been part of. Wrapping those initialisers one by one is
	 * whack-a-mole: latch, then GUCMemoryContext, then ControlFile.
	 *
	 * The mechanism to avoid this is already in add_fuzzers.diff, and this
	 * harness simply never used it. That patch wraps everything from the top
	 * of PostgresMain() down to the message loop in
	 * `if (fuzzer_first_run) { ... fuzzer_first_run = false; }`. So the call
	 * in LLVMFuzzerInitialize does the full single-user setup --
	 * CreateSharedMemoryAndSemaphores, InitPostgres, BaseInit (which is where
	 * InitializeLatchWaitSet lives) -- and clears the flag; every call after
	 * that skips the prologue entirely and drops straight into
	 * `for (;;) { ... ReadCommand ... }`, which is the only part worth
	 * fuzzing here.
	 *
	 * "dbfuzz" is the database dbfuzz.c actually creates, and the one every
	 * other harness connects to (InitPostgres("dbfuzz", ...) in
	 * fuzzer_initialize.c).
	 *
	 * It is NOT what PostgresSingleUserMain() derives. That passes no dbname
	 * in av[], so process_postgres_switches() finds none and falls back to the
	 * username -- "fuzzuser" -- which is not a database in the shipped data
	 * directory. InitPostgres then FATALs, errfinish calls proc_exit, and the
	 * longjmp out of it happens *before* fuzzer_first_run is cleared. So the
	 * guard never closed, every input re-ran the whole prologue, and the target
	 * died on whichever one-shot initialiser BaseInit reached first --
	 * LatchWaitSet, then MyProc, then SizeVfdCache as each was worked around.
	 *
	 * That is the original defect: this harness has been connecting to a
	 * database that does not exist for as long as it has existed, which is why
	 * it has executed one unit in every campaign.
	 */
	/*
	 * Per-input deadline, from a thread rather than the timeout table.
	 * PostgresMain's own startup calls InitializeTimeouts(), which clears
	 * the registration table, so nothing registered around this call
	 * survives to be armed -- three attempts died on
	 * Assert(all_timeouts[id].timeout_handler != NULL). See
	 * fuzz_deadline.h. This bounds every blocking path inside the backend,
	 * including orafce's dbms_alert.waitany().
	 */
	pgfuzz_deadline_arm();
	if(!sigsetjmp(postgre_exit, 0)){
		postgre_started = true;
		PostgresMain("dbfuzz", "fuzzuser");
	}
	pgfuzz_deadline_disarm();

	/*
	 * NO LWLOCK SURVIVES AN INPUT. Measured, not assumed:
	 *
	 *   held_lwlocks[0].lock = 0x7ffff3bb8b04
	 *   shmem_lockid         = 0x7ffff3bb8b04
	 *   SAME LOCK? 1
	 *
	 * caught by `break ora_lock_shmem if num_held_lwlocks > 0` on the 96th
	 * call. The target holds shmem_lockid and then acquires shmem_lockid --
	 * a self-deadlock on the identical lock, left over from an earlier input
	 * where orafce raised ereport(ERROR) from inside its own
	 * ora_lock_shmem/LWLockRelease pair (pipe.c: "pipe creation error").
	 *
	 * In an ordinary backend AbortTransaction() would have released it. This
	 * harness drives PostgresMain per input and unwinds through a longjmp, so
	 * that cleanup does not reliably run -- and releasing in __wrap_proc_exit
	 * is not enough either, because an ERROR is handled inside PostgresMain
	 * and never reaches proc_exit at all. That was the previous fix, and it
	 * left the deadlock in place.
	 *
	 * Releasing HERE, at the input boundary, is the one place that covers
	 * every exit path: normal return, longjmp from proc_exit, and an ERROR
	 * swallowed inside the message loop. LWLockReleaseAll() is void and
	 * cannot raise, and by this point no PostgreSQL code is running that
	 * could legitimately still hold one.
	 *
	 * NOT AbortOutOfAnyTransaction(): tried, and it crashes the NEXT input by
	 * destroying TopTransactionContext -- see __wrap_proc_exit.
	 */
	LWLockReleaseAll();
	/*
	 * The deadline above replaces the retreat that used to be recorded
	 * here. Three attempts to register a PostgreSQL timeout around
	 * PostgresMain aborted, because its startup clears the timeout
	 * table, and the target ran with nothing bounding a single input --
	 * an input that blocked cost ~7,110 s of a sweep slot, and orafce's
	 * dbms_alert.waitany() is reachable from here. The thread in
	 * fuzz_deadline.h needs neither SIGALRM nor that table.
	 * See FINDINGS/orafce-dbms-alert-waitany-hangs-the-fuzzer.
	 */
	end_msgread_if_reading();
	postgre_started = false;

	/*
	 * Did we actually read the input?  buffersize is decremented by
	 * __wrap_pq_getbyte, so size - buffersize is what the backend consumed.
	 * Expect this to report ~1 byte until pq_getbytes is wrapped too: only
	 * pq_getbyte is intercepted, so the message length and body go to the
	 * real pq_recvbuf and fail on the absent Port.  See fuzz_probe.h.
	 */
	pgfuzz_probe_consumed("protocol_fuzzer", size, size - buffersize);

	free(buffer);
	return 0;
}

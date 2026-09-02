/*-------------------------------------------------------------------------
 *
 * extension_funcs_fuzzer.c
 *	  Fuzz the SQL-callable functions that an extension adds, directly.
 *
 * backend_types_fuzzer reaches an extension's *input* functions, because those
 * are what a type name resolves to.  That is a small fraction of what an
 * extension is.  For one patched distribution's mchar type, a coverage run over a 382,694-input
 * corpus put mchar_io.c at 15% and mchar_recode.c at 30% while mchar_op.c and
 * mchar_proc.c -- the comparison operators and the functions, which is where
 * new logic in a patch like that actually lives -- sat at exactly 0%.
 *
 * Reaching them through SQL works but is indirect: the query targets have to
 * guess a syntactically valid statement *and* a value that survives the type's
 * input function before a single comparison happens.  This target starts from
 * the other end.  It asks the catalog which functions belong to the configured
 * extensions, resolves each one's argument types, and calls them through fmgr
 * with arguments built from the fuzzed bytes -- so every byte of the input is
 * spent on the arguments rather than on syntax.
 *
 * Nothing here knows about any particular extension.  The workspace's
 * `extensions=` setting is written to $OUT/extensions.txt by build.sh and read
 * at runtime, exactly as $OUT/extra_types.txt already is, so one binary serves
 * every workspace and a workspace that configures no extensions gets a target
 * that does nothing rather than a build failure.
 *
 * Each iteration runs inside its own transaction which is always aborted.
 * These are ordinary SQL functions and some of them write -- fasttrun's
 * fasttruncate() truncates a table -- so without that the database would drift
 * and no crash would reproduce.
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include "access/htup_details.h"
#include "access/xact.h"
#include "catalog/pg_collation_d.h"
#include "catalog/pg_proc.h"
#include "catalog/pg_type.h"
#include "executor/spi.h"
#include "fmgr.h"
#include "lib/stringinfo.h"
#include "miscadmin.h"
#include "storage/fd.h"			/* AllocateFile() */
#include "storage/latch.h"		/* SetLatch(), MyLatch */
#include "utils/builtins.h"
#include "utils/lsyscache.h"
#include "utils/memutils.h"
#include "utils/snapmgr.h"
#include "utils/syscache.h"
#include "utils/timeout.h"		/* RegisterTimeout(), enable_timeout_after() */

#include <setjmp.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>			/* write(), for the signal-context diagnostics */

/* provided by fuzzer_initialize.c */
#include "fuzz_canary.h"
#include "fuzz_probe.h"
#include "fuzz_lineage.h"

extern int	FuzzerInitialize(char *dbname, char ***argv);
extern char pgfuzz_out_dir[];

/*
 * The cap, and why it is this size.
 *
 * It was 256, which was fine for every workspace built before out-of-tree
 * plugins existed -- one such set discovers 154 -- and became wrong the moment one
 * did: orafce alone declares 582 functions.  With a 256 cap and extensions
 * walked in extensions.txt order, credcheck took 7 slots, orafce took the
 * remaining 249 of its 582, and pgaudit's discovery never ran at all.  Nothing
 * said so.
 *
 * 4096 is chosen to be larger than any plausible extension set rather than
 * "large enough for orafce": at ~110 bytes per entry this is ~450KB of static
 * data, which is nothing against a postgres backend, and the failure mode of
 * being too small is silent under-testing -- the worst kind here.
 *
 * The cap can still bind in principle, so it is now reported rather than
 * enforced quietly; see report_discovery().
 */
#define PGFUZZ_MAX_FUNCS	4096
#define PGFUZZ_MAX_EXTS		64
#define PGFUZZ_MAX_ARGS		3
#define MAX_INPUT_LEN		4096

/*
 * Argument separator.
 *
 * A single fuzzed buffer has to become N argument values.  Splitting it evenly
 * would tie the arguments together -- the fuzzer could not lengthen one
 * without shortening another -- so the split is explicit and the fuzzer
 * controls it.  0x1f (ASCII unit separator) is the natural choice: it is the
 * character the encoding exists for, and it is rare enough in the SQL corpora
 * these workspaces seed from that it does not collide with real content.
 *
 * Fewer separators than the function takes arguments is fine; the missing
 * trailing arguments are empty strings, which most input functions reject, and
 * a rejected input is a normal outcome rather than a finding.
 */
#define ARG_SEP		'\x1f'

/*
 * Only OIDs are cached, never FmgrInfo.
 *
 * The first version resolved fmgr_info_cxt(..., TopMemoryContext) once at
 * startup and reused those FmgrInfos for every iteration.  That crashes.  A
 * called function is entitled to cache per-call state in
 * fcinfo->flinfo->fn_extra, and many allocate it from the *current* context --
 * which here is the transaction context that AbortCurrentTransaction() frees
 * at the end of the iteration.  The next iteration then hands the callee an
 * fn_extra pointing into freed memory, and it dies in
 * Assert("!HdrMaskIsExternal(chunk->hdrmask) || HdrMaskCheckMagic(...)").
 * All eight workers hit it within seconds and the target managed about 5,000
 * executions in half an hour.
 *
 * Resolving per iteration inside the transaction makes fn_mcxt the transaction
 * context, so whatever the callee caches is freed with everything else and the
 * next iteration starts clean.  It costs a few syscache lookups per call,
 * which is nothing next to the transaction itself.
 */
typedef struct
{
	Oid			procoid;
	char		name[NAMEDATALEN];
	int			nargs;
	bool		isstrict;
	Oid			collation;		/* what SQL would pass; see below */
	Oid			argtypinput[PGFUZZ_MAX_ARGS];	/* input function per argument */
	Oid			argioparam[PGFUZZ_MAX_ARGS];
} FuzzFunc;

static FuzzFunc funcs[PGFUZZ_MAX_FUNCS];
static int	nfuncs = 0;

/*
 * Per-extension accounting, so "which extension got starved" is answerable.
 *
 * Without it, a cap that binds looks identical to an extension that simply has
 * no fuzzable functions, and the only visible number -- the total -- looks
 * healthy either way.
 */
typedef struct
{
	char		name[NAMEDATALEN];
	int			found;			/* rows pg_depend returned */
	int			used;			/* entries actually registered */
} ExtStat;

static ExtStat extstats[PGFUZZ_MAX_EXTS];
static int	nexts = 0;
static int	ndropped = 0;		/* functions the cap refused */

/*
 * Functions this harness must not call directly, by extension and/or schema.
 *
 * WHY A SKIP LIST EXISTS AT ALL, given that one was argued against twice:
 *
 * A deadline can bound a function that computes and returns. It cannot bound
 * one that takes an extension's own shared-memory lock, because cancelling
 * inside the locked region unwinds past the code that would release it -- only
 * the extension knows how. Observed directly: after the deadline cancelled 38
 * calls, the backend sat in futex_do_wait at 0% CPU waiting on an LWLock it
 * held itself, which LWLockAcquire cannot be interrupted out of.
 *
 * So this is not "these functions are troublesome". It is a boundary: direct
 * fmgr invocation cannot safely bound a callee holding a shared lock, and such
 * callees must be reached through SQL instead, where the executor arms
 * statement_timeout and PostgreSQL owns the cancellation.
 *
 * ENTRY FORMS, all matched case-sensitively against catalog names:
 *
 *     dbms_pipe          a schema, in any extension
 *     orafce.dbms_pipe   that schema, only in that extension
 *     orafce.*           every schema of that extension
 *     orafce             the extension entire (same as orafce.*)
 *
 * The bare form is a schema OR an extension name, because an Oracle-style
 * package maps one-to-one onto a schema and both readings are useful. The
 * qualified form exists so that two extensions shipping a schema of the same
 * name can be told apart, and so a whole plugin can be excluded if one ever
 * earns it -- though at plugin granularity orafce would cost 405 functions to
 * avoid 25, which is why schema is the default unit.
 */
#define PGFUZZ_MAX_SKIP		32

static char skips[PGFUZZ_MAX_SKIP][2 * NAMEDATALEN];
static int	nskips = 0;
static int	nskipped = 0;		/* functions the skip list refused */

/* Per-schema tally of what was skipped, so it is never merely absent. */
typedef struct
{
	char		name[2 * NAMEDATALEN];
	int			count;
} SkipStat;

static SkipStat skipstats[PGFUZZ_MAX_SKIP];
static int	nskipstats = 0;

/*
 * Does (extname, nspname) match any skip entry?
 */
static bool
is_skipped(const char *extname, const char *nspname)
{
	int			i;

	for (i = 0; i < nskips; i++)
	{
		const char *e = skips[i];
		const char *dot = strchr(e, '.');

		if (dot == NULL)
		{
			/* bare: a schema name or an extension name */
			if (strcmp(e, nspname) == 0 || strcmp(e, extname) == 0)
				return true;
			continue;
		}

		/* qualified: ext.schema, with '*' meaning every schema */
		if ((size_t) (dot - e) != strlen(extname) ||
			strncmp(e, extname, dot - e) != 0)
			continue;
		if (strcmp(dot + 1, "*") == 0 || strcmp(dot + 1, nspname) == 0)
			return true;
	}
	return false;
}

static void
note_skipped(const char *nspname)
{
	int			i;

	nskipped++;
	for (i = 0; i < nskipstats; i++)
		if (strcmp(skipstats[i].name, nspname) == 0)
		{
			skipstats[i].count++;
			return;
		}
	if (nskipstats < PGFUZZ_MAX_SKIP)
	{
		strlcpy(skipstats[nskipstats].name, nspname,
				sizeof(skipstats[nskipstats].name));
		skipstats[nskipstats].count = 1;
		nskipstats++;
	}
}

/*
 * Load the skip list: $OUT/extension_skip.txt if present, else the built-in
 * default. Per-workspace rather than compiled in, for the same reason plugin
 * versions are per-workspace -- which extensions are loaded is the experiment
 * variable, so what must be skipped follows from it and cannot be a property
 * of the harness. An empty file means "skip nothing", deliberately: that is how
 * you reproduce the deadlock on purpose.
 */
static void
load_skips(void)
{
	static const char *const defaults[] = {
		"dbms_alert", "dbms_pipe", "dbms_lock", NULL
	};
	char		path[MAXPGPATH];
	FILE	   *fp;
	int			i;

	snprintf(path, sizeof(path), "%s/extension_skip.txt", pgfuzz_out_dir);
	fp = AllocateFile(path, "r");
	if (fp == NULL)
	{
		for (i = 0; defaults[i] != NULL && nskips < PGFUZZ_MAX_SKIP; i++)
			strlcpy(skips[nskips++], defaults[i], sizeof(skips[0]));
		return;
	}

	{
		char		line[2 * NAMEDATALEN];

		while (fgets(line, sizeof(line), fp) != NULL && nskips < PGFUZZ_MAX_SKIP)
		{
			char	   *nl = strchr(line, '\n');

			if (nl)
				*nl = '\0';
			if (line[0] == '\0' || line[0] == '#')
				continue;
			strlcpy(skips[nskips++], line, sizeof(skips[0]));
		}
	}
	FreeFile(fp);
}

/*
 * A call deadline, because an extension function is entitled to block.
 *
 * orafce ships 38 functions in the dbms_alert / dbms_pipe / dbms_lock families
 * -- waitany, waitone, receive_message -- that wait on a latch for as long as
 * their *timeout argument* says. That argument is fuzzed like any other, and
 * float8in reaches 1e9 sooner or later, which is 31 years. The function is
 * behaving exactly as documented; it was asked to wait. One such input parked a
 * worker for 3h28m and stalled a whole campaign on target 7 of 23.
 *
 * Nothing else bounds it:
 *   - libFuzzer's -timeout and -max_total_time are evaluated *between*
 *     iterations, and an iteration that never returns is never timed.
 *   - statement_timeout is armed by exec_simple_query() in postgres.c. This
 *     harness calls through fmgr directly and never goes near it.
 *
 * The callee was interruptible the whole time -- orafce's loop caps each sleep
 * at one second and ConditionVariableTimedSleep() checks for interrupts on
 * every wake, so it woke ~12,500 times looking for a reason to stop and found
 * none. Nobody had armed one. So arm one.
 *
 * Deliberately NOT a denylist of the three functions found so far: this is a
 * property of any caller-supplied duration argument, so naming the instances
 * would leave the class open for the next plugin.
 *
 * STATEMENT_TIMEOUT itself is registered by PostgresMain(), which this harness
 * never calls, so we register our own id rather than depend on that.
 */
/*
 * 250ms, and the number matters more than it looks.
 *
 * The first version used 5 seconds, which worked -- the deadline fired and the
 * call was cancelled every time -- and still ruined the campaign, because
 * roughly one input in twenty selects a function that blocks, and each one then
 * cost the full five seconds. Measured directly: 100 runs of one blocking input
 * took 505,056 ms, i.e. 5.05 s each. A 300-second budget cannot survive that,
 * and libFuzzer's corpus replay at startup cannot either -- which is why round 2
 * of the last campaign reported zero executions while looking like a hang.
 *
 * Time spent blocked is pure dead time: no coverage is gained while waiting on
 * a latch. So the deadline only has to be long enough that a *legitimately*
 * slow function is not cut short, and 250ms is far beyond anything these
 * argument-driven calls need. It makes a blocking input cost 1/20th of what it
 * did.
 */
#define PGFUZZ_CALL_TIMEOUT_MS	250

static int	fuzz_timeout_id = -1;

/* How many calls hit the deadline. sig_atomic_t: written from signal context. */
static volatile sig_atomic_t fuzz_timeouts_fired = 0;

/* Total calls attempted, for the ratio that actually matters. */
static uint64 fuzz_calls = 0;

static void
fuzz_call_timeout_handler(void)
{
	/*
	 * Counted, not printed.
	 *
	 * This briefly wrote a line per firing, which is how the "hang" was
	 * identified as 5 seconds x many blocking inputs rather than a deadlock.
	 * At campaign scale that is millions of lines into the run log, so it is a
	 * counter now; report_discovery() publishes it, which is the same rule the
	 * rest of this harness follows -- a number nobody can see is a number that
	 * is wrong.
	 */
	fuzz_timeouts_fired++;

	/*
	 * Mirrors StatementTimeoutHandler(). The latch matters: the callee may be
	 * asleep in ConditionVariableTimedSleep(), and setting it wakes that sleep
	 * now rather than at the end of its current one-second slice.
	 */
	InterruptPending = true;
	QueryCancelPending = true;
	SetLatch(MyLatch);
}

/*
 * Take SIGALRM back from libFuzzer, once, at the first input.
 *
 * PostgreSQL and libFuzzer both want the same single process-wide clock:
 * PostgreSQL's timeout.c uses setitimer(ITIMER_REAL) with handle_sig_alarm,
 * and libFuzzer's -timeout watchdog uses setitimer(ITIMER_REAL) with
 * fuzzer::AlarmHandler. Both symbols are in this binary; only one handler can
 * be installed.
 *
 * Order decides it, and the order is against us: InitializeTimeouts() runs
 * inside FuzzerInitialize(), i.e. during LLVMFuzzerInitialize, and libFuzzer
 * calls SetTimer() *after* that returns. So PostgreSQL's handler is installed
 * first and immediately overwritten, and enable_timeout_after() then arms a
 * timer whose signal is delivered to libFuzzer's handler, which knows nothing
 * about it. QueryCancelPending is never set and the deadline never fires.
 *
 * That cost a full campaign to learn: the first version of this timeout was
 * registered in LLVMFuzzerInitialize and did nothing at all, and a blocking
 * orafce call still held a worker until the campaign watchdog killed it -- in
 * round 2, before a single input had been executed, because the blocking input
 * was by then sitting in the corpus and libFuzzer replays the corpus first.
 *
 * It also explains why libFuzzer's own -timeout=25 did not save us either:
 * arming our one-shot timer replaced libFuzzer's repeating one, so after our
 * signal was delivered to its handler (which saw nothing overdue and returned)
 * no further SIGALRM was ever scheduled. Two timeout mechanisms, one timer,
 * neither working.
 *
 * InitializeTimeouts() is explicitly re-entrant -- its own comment says
 * "Initialize, or re-initialize" -- and it reinstalls handle_sig_alarm. It
 * clears the registration table, so the timeout has to be registered again
 * afterwards.
 *
 * The cost is libFuzzer's -timeout, which no longer has a clock. That is not a
 * loss: it demonstrably was not working in this harness anyway, and a deadline
 * that fires is worth more than one that does not.
 */
static void
reclaim_sigalrm(void)
{
	static bool done = false;

	if (done)
		return;
	done = true;

	InitializeTimeouts();		/* reinstalls handle_sig_alarm; clears the table */
	fuzz_timeout_id = RegisterTimeout(USER_TIMEOUT, fuzz_call_timeout_handler);

}

/*
 * Ask the catalog which functions belong to the named extension.
 *
 * pg_depend with deptype 'e' is the authoritative answer -- it is how DROP
 * EXTENSION knows what to drop -- and it is exact in a way that matching on a
 * name prefix or a schema is not.
 *
 * The filters are about what can be *called* with synthesized arguments, not
 * about what is interesting:
 *
 *	prokind = 'f'		 aggregates and window functions are not callable
 *						 through FunctionCallInvoke; they need an aggregate
 *						 context that does not exist here.
 *	NOT proretset		 a set-returning function called without a
 *						 ReturnSetInfo either errors or misbehaves, and the
 *						 error is ours, not PostgreSQL's.
 *
 * Argument types are filtered in C below rather than here: pseudo-types
 * (internal, cstring, anyelement, record, trigger, ...) have no value we
 * could construct, and passing a fabricated Datum as `internal` is a pointer
 * the callee will dereference -- a crash we manufactured, not one we found.
 * Doing it in C also avoids depending on the oidvector-to-oid[] cast that
 * unnest(proargtypes) would need, and the proc tuple is fetched there anyway.
 */
static void
discover_extension_funcs(const char *extname)
{
	StringInfoData sql;
	int			ret;
	uint64		i;
	int			nbefore;

	initStringInfo(&sql);
	appendStringInfo(&sql,
					 "SELECT p.oid, n.nspname FROM pg_proc p "
					 "JOIN pg_depend d ON d.classid = 'pg_proc'::regclass "
					 "  AND d.objid = p.oid AND d.deptype = 'e' "
					 "JOIN pg_extension e ON e.oid = d.refobjid "
					 "JOIN pg_namespace n ON n.oid = p.pronamespace "
					 "WHERE e.extname = %s "
					 "  AND p.prokind = 'f' AND NOT p.proretset "
					 "  AND p.pronargs BETWEEN 1 AND %d "
					 "ORDER BY p.oid",
					 quote_literal_cstr(extname), PGFUZZ_MAX_ARGS);

	if (SPI_connect() != SPI_OK_CONNECT)
	{
		pfree(sql.data);
		return;
	}

	ret = SPI_execute(sql.data, true, 0);
	if (ret != SPI_OK_SELECT)
	{
		SPI_finish();
		pfree(sql.data);
		return;
	}

	/* Record this extension before the loop, so an extension that contributes
	 * nothing still appears in the report with the count it was entitled to. */
	if (nexts < PGFUZZ_MAX_EXTS)
	{
		strlcpy(extstats[nexts].name, extname, sizeof(extstats[nexts].name));
		extstats[nexts].found = (int) SPI_processed;
		extstats[nexts].used = 0;
		nexts++;
	}
	nbefore = nfuncs;

	for (i = 0; i < SPI_processed; i++)
	{
		bool		isnull;
		Datum		d;
		Oid			procoid;
		HeapTuple	tup;
		Form_pg_proc pform;
		FuzzFunc   *f;
		int			j;
		bool		ok = true;

		/*
		 * Out of room: count what is being refused instead of walking off the
		 * end of the array, and stop.  The remaining rows are attributed as
		 * dropped without asking whether each would have survived the argument
		 * type checks below, so this over-counts slightly -- an upper bound on
		 * what was lost is the useful direction to be wrong in.
		 */
		if (nfuncs >= PGFUZZ_MAX_FUNCS)
		{
			ndropped += (int) SPI_processed - i;
			break;
		}

		d = SPI_getbinval(SPI_tuptable->vals[i], SPI_tuptable->tupdesc, 1, &isnull);
		if (isnull)
			continue;
		procoid = DatumGetObjectId(d);

		/*
		 * Skip before any other work: a function excluded by plugin or by
		 * schema must not be registered, and must be counted so that
		 * "excluded" is distinguishable from "absent".
		 */
		{
			char	   *nspname = SPI_getvalue(SPI_tuptable->vals[i],
											   SPI_tuptable->tupdesc, 2);

			if (nspname != NULL && is_skipped(extname, nspname))
			{
				note_skipped(nspname);
				continue;
			}
		}

		tup = SearchSysCache1(PROCOID, ObjectIdGetDatum(procoid));
		if (!HeapTupleIsValid(tup))
			continue;
		pform = (Form_pg_proc) GETSTRUCT(tup);

		f = &funcs[nfuncs];
		f->procoid = procoid;
		strlcpy(f->name, NameStr(pform->proname), sizeof(f->name));
		f->nargs = pform->pronargs;
		f->isstrict = pform->proisstrict;

		/*
		 * Collation, derived the way the parser derives it: from the first
		 * collatable argument's typcollation, and InvalidOid when no argument
		 * is collatable.
		 *
		 * Passing DEFAULT_COLLATION_OID unconditionally, as the first version
		 * did, hands functions a collation SQL can never hand them. mchar is
		 * declared without COLLATABLE, so its typcollation is 0 and the
		 * executor always passes InvalidOid; mchar_regexeq reads
		 * PG_GET_COLLATION() and a non-zero value sends it down a path no
		 * query can reach. That produced a reproducible palloc chunk-header
		 * corruption which looked exactly like a real defect in the patch --
		 * eight artifacts, one clean signature, narrowed neatly to the regex
		 * operators -- and was manufactured entirely here.
		 *
		 * A crash only counts if a client can cause it. Getting the calling
		 * convention wrong does not find bugs, it invents them.
		 */
		f->collation = InvalidOid;
		for (j = 0; j < f->nargs; j++)
		{
			Oid			coll = get_typcollation(pform->proargtypes.values[j]);

			if (OidIsValid(coll))
			{
				f->collation = coll;
				break;
			}
		}

		for (j = 0; j < f->nargs; j++)
		{
			Oid			argtype = pform->proargtypes.values[j];
			Oid			typinput;

			if (get_typtype(argtype) == TYPTYPE_PSEUDO)
			{
				ok = false;
				break;
			}

			getTypeInputInfo(argtype, &typinput, &f->argioparam[j]);
			if (!OidIsValid(typinput))
			{
				ok = false;
				break;
			}
			f->argtypinput[j] = typinput;
		}

		if (ok)
			nfuncs++;

		ReleaseSysCache(tup);
	}

	if (nexts > 0)
		extstats[nexts - 1].used = nfuncs - nbefore;

	SPI_finish();
	pfree(sql.data);
}

/*
 * Report what was found to a file, for the same reason backend_types_fuzzer
 * does: FuzzerInitialize() sets whereToSendOutput = DestNone, so an elog()
 * here goes nowhere, and "did this target find anything to call" would
 * otherwise be unobservable from outside -- which is exactly how a target that
 * silently does nothing survives a whole campaign looking busy.
 */
static void
report_discovery(void)
{
	char		path[MAXPGPATH];
	FILE	   *fp;
	int			i;

	snprintf(path, sizeof(path), "%s/extension_funcs.loaded", pgfuzz_out_dir);
	fp = AllocateFile(path, "w");
	if (fp == NULL)
		return;

	fprintf(fp, "functions: %d\n", nfuncs);
	fprintf(fp, "cap: %d\n", PGFUZZ_MAX_FUNCS);
	fprintf(fp, "dropped: %d\n", ndropped);
	/*
	 * How many calls were cut short at the deadline. A large number is not an
	 * error -- some extensions simply expose functions that wait -- but it is
	 * time bought no coverage with, and if it ever approaches the execution
	 * count then the target is spending its budget waiting rather than testing.
	 * That is exactly what happened at a 5-second deadline, and it presented as
	 * a hang rather than as a number.
	 */
	fprintf(fp, "timeouts_fired: %d\n", (int) fuzz_timeouts_fired);
	fprintf(fp, "timeout_ms: %d\n", PGFUZZ_CALL_TIMEOUT_MS);
	fprintf(fp, "calls: %llu\n", (unsigned long long) fuzz_calls);

	/*
	 * The skip list and its effect, always -- an excluded function must never
	 * be indistinguishable from one that does not exist. Reading "orafce: found
	 * 449, used 383" without this would look like 66 functions quietly failing
	 * to register.
	 */
	fprintf(fp, "skipped_unsafe: %d\n", nskipped);
	{
		int			k;

		fprintf(fp, "skip_list:");
		for (k = 0; k < nskips; k++)
			fprintf(fp, " %s", skips[k]);
		fprintf(fp, "%s\n", nskips == 0 ? " (none)" : "");
		for (k = 0; k < nskipstats; k++)
			fprintf(fp, "  skipped %s: %d\n",
					skipstats[k].name, skipstats[k].count);
	}

	/*
	 * Per-extension, always -- not only when something was dropped.  "found"
	 * is what pg_depend returned; "used" is what is actually reachable.  A gap
	 * between them is either the cap biting or argument types this harness
	 * cannot build, and both are things you want to see before reading a
	 * coverage number for that extension.
	 */
	for (i = 0; i < nexts; i++)
		fprintf(fp, "  ext %s: found %d, used %d\n",
				extstats[i].name, extstats[i].found, extstats[i].used);

	if (ndropped > 0)
		fprintf(fp, "WARNING: cap reached -- %d function(s) are UNREACHABLE; "
				"raise PGFUZZ_MAX_FUNCS\n", ndropped);

	for (i = 0; i < nfuncs; i++)
		fprintf(fp, "  %s/%d%s\n", funcs[i].name, funcs[i].nargs,
				funcs[i].isstrict ? "" : " (not strict)");
	FreeFile(fp);
}

int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
	char		path[MAXPGPATH];
	FILE	   *fp;
	MemoryContext oldctx;

	FuzzerInitialize("extension_funcs_db", argv);
	pgfuzz_canary_init();

	/*
	 * NOT here -- see reclaim_sigalrm() at the first input. Registering the
	 * deadline in this function is useless: libFuzzer installs its own SIGALRM
	 * handler *after* LLVMFuzzerInitialize returns, so whatever we set up here
	 * is overwritten before a single input runs.
	 */

	load_skips();

	snprintf(path, sizeof(path), "%s/extensions.txt", pgfuzz_out_dir);
	fp = AllocateFile(path, "r");
	if (fp == NULL)
	{
		/*
		 * No extensions configured for this workspace.  Not an error: the same
		 * binary is built for every workspace and most have none.
		 */
		report_discovery();
		return 0;
	}

	StartTransactionCommand();
	PushActiveSnapshot(GetTransactionSnapshot());
	oldctx = MemoryContextSwitchTo(TopMemoryContext);

	{
		char		line[NAMEDATALEN];

		/*
		 * Every extension is visited, even once the cap is full.  Stopping the
		 * loop early was how pgaudit came to be preloaded, created, and never
		 * called: orafce filled the array first and pgaudit's line was simply
		 * never read, so it appeared nowhere -- not in the function list, and
		 * not in any count of what was missing.  discover_extension_funcs()
		 * now records the extension and what it was owed before it registers
		 * anything, so a starved extension is visible rather than absent.
		 */
		while (fgets(line, sizeof(line), fp) != NULL)
		{
			char	   *nl = strchr(line, '\n');

			if (nl)
				*nl = '\0';
			if (line[0] == '\0')
				continue;

			/*
			 * An extension that is not installed, or a catalog query that
			 * errors, must not take the target down: FuzzerInitialize() has
			 * not installed a PG_exception_stack, so an uncaught ereport here
			 * aborts the process before a single input runs.
			 */
			PG_TRY();
			{
				discover_extension_funcs(line);
			}
			PG_CATCH();
			{
				MemoryContextSwitchTo(TopMemoryContext);
				FlushErrorState();
			}
			PG_END_TRY();
		}
	}

	FreeFile(fp);

	MemoryContextSwitchTo(oldctx);
	PopActiveSnapshot();
	AbortCurrentTransaction();

	report_discovery();
	return 0;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	sigjmp_buf	local_sigjmp_buf;
	char	   *buf;
	FuzzFunc   *f;
	int			sel;
	uint8		nullmap;

	/* Per-iteration stack base; see the note in fuzz_util.h:pgfuzz_run(). */
	set_stack_base();

	/* Must happen after libFuzzer has installed its own SIGALRM handler. */
	reclaim_sigalrm();

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

	if (nfuncs == 0 || size < 3 || size > MAX_INPUT_LEN)
		return 0;

	/*
	 * THREE control bytes: a 16-bit little-endian function selector, then the
	 * null map, then the argument text.
	 *
	 * The selector was one byte, which silently bounded this target at 256
	 * reachable functions no matter how large the cap was -- data[0] % nfuncs
	 * cannot exceed 255, so with 591 functions discovered, indices 256..590
	 * could never be selected. Raising PGFUZZ_MAX_FUNCS alone would have
	 * discovered more functions and still called none of them, which is a worse
	 * bug than the one it replaces: the report would say 591 and the fuzzer
	 * would reach 256.
	 *
	 * Little-endian so that libFuzzer's byte-level mutations of data[0] walk
	 * neighbouring functions (cheap, local exploration) while data[1] jumps in
	 * strides of 256 (coarse exploration) -- both useful, and it keeps the
	 * low byte doing what it did before.
	 *
	 * The null map is only consulted for non-strict functions: the executor
	 * never calls a strict function with a NULL argument, so doing it here
	 * would be testing a calling convention PostgreSQL does not use.  For a
	 * non-strict function it is the whole point -- fulleq exists precisely to
	 * define what equality means when an argument is NULL.
	 *
	 * In int arithmetic, not uint16: a workspace supplying exactly 65536
	 * functions would make (uint16) nfuncs zero and divide by it.
	 */
	sel = (int) ((uint32) data[0] | ((uint32) data[1] << 8)) % nfuncs;
	nullmap = data[2];
	f = &funcs[sel];

	data += 3;
	size -= 3;

	buf = (char *) malloc(size + 1);
	if (buf == NULL)
		return 0;
	memcpy(buf, data, size);
	buf[size] = '\0';

	if (sigsetjmp(local_sigjmp_buf, 0) == 0)
	{
		LOCAL_FCINFO(fcinfo, PGFUZZ_MAX_ARGS);
		FmgrInfo	finfo;
		FmgrInfo	arginfo[PGFUZZ_MAX_ARGS];
		char	   *piece = buf;
		int			j;

		PG_exception_stack = &local_sigjmp_buf;
		error_context_stack = NULL;

		/*
		 * Arm the deadline HERE, not just around FunctionCallInvoke.
		 *
		 * Bracketing only the call left everything else unprotected --
		 * transaction start, snapshot, per-argument input functions -- and the
		 * evidence says that is where the target stops: it stalls after ~1000
		 * iterations with `timeouts_fired: 0`, which cannot happen if the stall
		 * were inside the call, because the deadline would have fired and
		 * cancelled it. Protecting only the part already known to be slow is
		 * how you arrive at an instrument that proves the problem is somewhere
		 * you did not instrument.
		 */
		if (fuzz_timeout_id >= 0)
			enable_timeout_after(fuzz_timeout_id, PGFUZZ_CALL_TIMEOUT_MS);

		StartTransactionCommand();
		PushActiveSnapshot(GetTransactionSnapshot());

		/* inside the transaction, so fn_mcxt dies with it -- see FuzzFunc */
		fmgr_info(f->procoid, &finfo);
		for (j = 0; j < f->nargs; j++)
			fmgr_info(f->argtypinput[j], &arginfo[j]);

		InitFunctionCallInfoData(*fcinfo, &finfo, f->nargs,
								 f->collation, NULL, NULL);

		for (j = 0; j < f->nargs; j++)
		{
			char	   *sep = strchr(piece, ARG_SEP);

			if (sep != NULL)
				*sep = '\0';

			if (!f->isstrict && (nullmap & (1 << j)))
			{
				fcinfo->args[j].value = (Datum) 0;
				fcinfo->args[j].isnull = true;
			}
			else
			{
				/*
				 * A value the type's input function rejects is the normal
				 * case, not a finding: it siglongjmps to the handler below
				 * and the iteration ends there.
				 */
				fcinfo->args[j].value = InputFunctionCall(&arginfo[j],
														  piece,
														  f->argioparam[j],
														  -1);
				fcinfo->args[j].isnull = false;
			}

			if (sep == NULL)
			{
				/*
				 * Ran out of input before running out of parameters.  Rather
				 * than feed the same trailing text to every remaining
				 * argument -- which would make the arguments correlated and
				 * waste most of the search -- treat it as an empty string for
				 * the rest and let the input functions decide.
				 */
				piece = buf + size;
			}
			else
				piece = sep + 1;
		}

		/*
		 * Already armed above, covering this call and everything before it in
		 * the iteration. A function that blocks past the deadline raises
		 * ERRCODE_QUERY_CANCELED at the callee's next interrupt check, which
		 * the recovery arm below already handles -- so a hang becomes an
		 * ordinary rejected input rather than a stalled campaign.
		 */
		(void) FunctionCallInvoke(fcinfo);

		if (fuzz_timeout_id >= 0)
			disable_timeout(fuzz_timeout_id, false);

		PopActiveSnapshot();
		AbortCurrentTransaction();
	}
	else
	{
		/* fall through to the shared bookkeeping below */
		/*
		 * The function or one of its arguments raised an ERROR -- normal.
		 *
		 * Disarm here too. A timeout that *fired* is already inactive, but an
		 * ERROR from anywhere else leaves ours armed, and it would then fire
		 * during a later iteration and cancel an unrelated call.
		 */
		if (fuzz_timeout_id >= 0)
			disable_timeout(fuzz_timeout_id, false);

		MemoryContextSwitchTo(TopMemoryContext);
		FlushErrorState();
		AbortCurrentTransaction();
	}

	PG_exception_stack = NULL;
	error_context_stack = NULL;

	MemoryContextSwitchTo(TopMemoryContext);
	MemoryContextReset(MessageContext);

	/*
	 * Republish the counters periodically, because publishing them once at
	 * startup -- which is what report_discovery() did on its own -- meant
	 * `timeouts_fired` was written before a single call had been made and was
	 * therefore always 0. The number added specifically to make blocked time
	 * visible was structurally incapable of showing any.
	 *
	 * Periodic, not atexit: a wedged target is killed with SIGKILL by the
	 * campaign watchdog, so anything deferred to exit is never written. Once
	 * every 256 calls costs nothing and survives the kill, which is precisely
	 * the case the number exists for.
	 *
	 * 256 rather than 4096, because the first threshold was larger than the
	 * problem: the target stalls after roughly a thousand calls, and at 4096
	 * the file was still reading `calls: 0` when the stall arrived. An
	 * instrument whose sampling interval exceeds the event it measures reports
	 * nothing, twice over -- this is the second time that has cost a cycle
	 * here.
	 */
	if ((++fuzz_calls & 0xFF) == 0)
		report_discovery();

	free(buf);

	/*
	 * See fuzz_canary.h: reachable-but-growing state is invisible to LSan.
	 * Note the pointer arithmetic above -- `data` has already been advanced
	 * past the three control bytes and `size` reduced to match, so what is
	 * hashed is the argument text, which is the part that varies.
	 */
	pgfuzz_canary_check(data, size);
	return 0;
}

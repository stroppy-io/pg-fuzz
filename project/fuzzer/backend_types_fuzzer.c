/*-------------------------------------------------------------------------
 *
 * backend_types_fuzzer.c
 *	  Fuzz the type input functions that need a catalog.
 *
 * array_in, record_in, range_in and multirange_in all parse a container
 * syntax and then dispatch to the *element* type's input function, which they
 * look up in pg_type.  aclitemin resolves role names through pg_authid.  None
 * of that works without a live backend, which is why these are split out of
 * scalar_types_fuzzer.c -- calling them standalone would crash on catalog
 * access and produce nothing but false positives.
 *
 * array_in is the most interesting of the set: it parses dimension bounds
 * ("[1:3][1:2]={{1,2},...}") from the input and allocates from them, then
 * fills the result by calling the element input function once per element.
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include "access/xact.h"
#include "catalog/pg_type_d.h"
#include "fmgr.h"
#include "lib/stringinfo.h"
#include "miscadmin.h"
#include "utils/fmgrprotos.h"
#include "utils/lsyscache.h"
#include "parser/parse_type.h"   /* TypenameGetTypid() */
#include "storage/fd.h"           /* AllocateFile() */
#include "utils/memutils.h"

#include <setjmp.h>
#include <stdlib.h>
#include <string.h>

/* provided by fuzzer_initialize.c */
#include "fuzz_canary.h"
#include "fuzz_probe.h"
#include "fuzz_timeout.h"
#include "fuzz_lineage.h"

extern int	FuzzerInitialize(char *dbname, char ***argv);
extern char pgfuzz_out_dir[];

/*
 * Types are named by OID and their input functions are resolved through the
 * catalog at startup, rather than calling array_in/range_in/etc. directly
 * with DirectFunctionCall3.
 *
 * That is not a stylistic preference.  DirectFunctionCallN builds a
 * FunctionCallInfo with flinfo == NULL, and every one of these input
 * functions caches its per-type lookup in fcinfo->flinfo->fn_extra:
 * array_in stashes an ArrayMetaState, range_in and multirange_in a
 * RangeIOData.  So the very first call dereferenced NULL and the target
 * SEGV'd in get_range_io_data() (rangetypes.c) on a one-byte input.  It
 * executed *zero* units in all 24 workspaces of the 2026-08-02 campaign
 * while producing 83 artifacts -- all of them that same crash.
 *
 * getTypeInputInfo() + fmgr_info() + InputFunctionCall() is how the backend
 * itself calls a type input function, and it supplies both the FmgrInfo the
 * caching needs and the correct typioparam, instead of one hand-maintained
 * here.
 */
typedef struct
{
	const char *name;
	Oid			typid;			/* 0 => resolve from elem at startup */
	Oid			elem;			/* for array types, the element type */
} type_entry;

static type_entry variants[] = {
	{"int4[]", InvalidOid, INT4OID},
	{"int8[]", InvalidOid, INT8OID},
	{"float8[]", InvalidOid, FLOAT8OID},
	{"text[]", InvalidOid, TEXTOID},
	{"numeric[]", InvalidOid, NUMERICOID},
	{"bool[]", InvalidOid, BOOLOID},
	{"bytea[]", InvalidOid, BYTEAOID},
	{"timestamp[]", InvalidOid, TIMESTAMPOID},
	{"inet[]", InvalidOid, INETOID},
	{"jsonb[]", InvalidOid, JSONBOID},
	{"int4range", INT4RANGEOID, InvalidOid},
	{"numrange", NUMRANGEOID, InvalidOid},
	{"tsrange", TSRANGEOID, InvalidOid},
	{"daterange", DATERANGEOID, InvalidOid},
	{"int4multirange", INT4MULTIRANGEOID, InvalidOid},
	{"nummultirange", NUMMULTIRANGEOID, InvalidOid},
	{"aclitem", ACLITEMOID, InvalidOid},
	{"regtype", REGTYPEOID, InvalidOid},
	{"regproc", REGPROCOID, InvalidOid},
	{"regclass", REGCLASSOID, InvalidOid},
};

/*
 * Resolved once, in TopMemoryContext, and reused: fn_extra caching is the
 * whole point of holding a persistent FmgrInfo, and it is also what a real
 * backend does across the rows of one scan.
 */
static FmgrInfo flinfo[lengthof(variants)];
static Oid	typioparam[lengthof(variants)];
static bool variants_ready[lengthof(variants)];

/* Workspace-configured extra types; see LLVMFuzzerInitialize. */
#define PGFUZZ_MAX_EXTRA 16
static FmgrInfo extra_flinfo[PGFUZZ_MAX_EXTRA];
static Oid	extra_typioparam[PGFUZZ_MAX_EXTRA];
static char extra_names[PGFUZZ_MAX_EXTRA][NAMEDATALEN];
static int	nextra = 0;
static char failed_names[PGFUZZ_MAX_EXTRA][NAMEDATALEN * 4];
static int	nfailed = 0;

int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
	MemoryContext oldctx;
	int			i;

	FuzzerInitialize("backend_types_db", argv);
	pgfuzz_canary_init();

	/*
	 * Resolve every variant's input function now.  The FmgrInfo must outlive
	 * the per-iteration context, so build them in TopMemoryContext.
	 *
	 * A lookup that fails is skipped rather than fatal: multirange types do
	 * not exist before PostgreSQL 14, and this harness is built against every
	 * branch from 16 to master, so one missing type must not take the whole
	 * target down -- which is the failure mode this fix exists to remove.
	 */
	/*
	 * The lookups below go through the syscache, and catcache.c asserts
	 * IsTransactionState().  A real backend never touches the catalog outside
	 * a transaction; neither may we.
	 */
	StartTransactionCommand();
	oldctx = MemoryContextSwitchTo(TopMemoryContext);
	for (i = 0; i < lengthof(variants); i++)
	{
		Oid			typid = variants[i].typid;
		Oid			typinput;

		if (!OidIsValid(typid) && OidIsValid(variants[i].elem))
			typid = get_array_type(variants[i].elem);
		if (!OidIsValid(typid))
			continue;

		variants[i].typid = typid;
		getTypeInputInfo(typid, &typinput, &typioparam[i]);
		if (!OidIsValid(typinput))
			continue;
		fmgr_info(typinput, &flinfo[i]);
		variants_ready[i] = true;
	}
	/*
	 * Extra types named in $OUT/extra_types.txt, written by build.sh from the
	 * workspace's `extra_types=` setting.
	 *
	 * Read at runtime rather than compiled in, so one binary serves every
	 * workspace and the list changes without a rebuild. Resolved by *name*
	 * because an extension's types have no compile-time OID in pg_type_d.h.
	 * A name that does not resolve is skipped, not fatal: the same build runs
	 * on workspaces where the extension was never created.
	 *
	 * This is what lets a patch under evaluation actually be fuzzed. Nothing
	 * here knows which patch -- the workspace supplies the names.
	 */
	{
		char		path[MAXPGPATH];
		FILE	   *fp;

		snprintf(path, sizeof(path), "%s/extra_types.txt", pgfuzz_out_dir);
		fp = AllocateFile(path, "r");

		if (fp != NULL)
		{
			char		line[NAMEDATALEN];

			while (fgets(line, sizeof(line), fp) != NULL &&
				   nextra < lengthof(extra_flinfo))
			{
				Oid			typid,
							typinput;
				char	   *nl = strchr(line, '\n');

				if (nl)
					*nl = '\0';
				if (line[0] == '\0')
					continue;

				/*
				 * PG_TRY, because "skipped, not fatal" has to be true for
				 * *errors*, not just for a name that fails to resolve.
				 * fmgr_info() on an extension's input function dlopens the
				 * extension's library, and any ereport(ERROR) on that path
				 * runs with no PG_exception_stack -- FuzzerInitialize does not
				 * install one -- so it killed the process before libFuzzer
				 * printed a single line. rc=1, zero bytes of output: the
				 * "config or preload failure before logging is up" signature,
				 * with logging additionally suppressed by
				 * whereToSendOutput = DestNone.
				 *
				 * PG_TRY installs its own handler, so this works even though
				 * nothing else here has.
				 */
				PG_TRY();
				{
					typid = TypenameGetTypid(line);
					if (OidIsValid(typid))
					{
						getTypeInputInfo(typid, &typinput,
										 &extra_typioparam[nextra]);
						if (OidIsValid(typinput))
						{
							fmgr_info(typinput, &extra_flinfo[nextra]);
							strlcpy(extra_names[nextra], line, NAMEDATALEN);
							nextra++;
						}
					}
				}
				PG_CATCH();
				{
					/*
					 * Record the failure *with its message*. Knowing that
					 * mchar failed to resolve narrowed nothing -- the library
					 * was present, the extension was created, the search path
					 * looked right -- and three separate hypotheses were tried
					 * before this. The error text was available the whole time
					 * and simply thrown away by FlushErrorState().
					 */
					ErrorData  *edata;
					MemoryContext ecxt;

					ecxt = MemoryContextSwitchTo(TopMemoryContext);
					edata = CopyErrorData();
					snprintf(failed_names[nfailed], sizeof(failed_names[0]), "%s: %s",
							 line, edata->message ? edata->message : "?");
					FreeErrorData(edata);
					MemoryContextSwitchTo(ecxt);

					FlushErrorState();
					if (nfailed < PGFUZZ_MAX_EXTRA - 1)
						nfailed++;
				}
				PG_END_TRY();
			}
			FreeFile(fp);

			/*
			 * Report to a file, not to the log.
			 *
			 * FuzzerInitialize() sets whereToSendOutput = DestNone and
			 * Log_destination = 0, so elog(LOG) here goes nowhere -- a
			 * diagnostic written into a harness that suppresses diagnostics.
			 * That left the one thing worth knowing, "did mchar actually
			 * resolve", unobservable from outside.
			 *
			 * $OUT is writable and is where extra_types.txt was read from, so
			 * the answer lands next to the question.
			 */
			{
				char		rpath[MAXPGPATH];
					FILE	   *rp;

					snprintf(rpath, sizeof(rpath), "%s/extra_types.loaded", pgfuzz_out_dir);
					rp = AllocateFile(rpath, "w");

				if (rp != NULL)
				{
					int			k;

					fprintf(rp, "requested: see extra_types.txt\n");
					fprintf(rp, "resolved: %d\n", nextra);
					for (k = 0; k < nextra; k++)
						fprintf(rp, "  %s\n", extra_names[k]);
					fprintf(rp, "failed: %d\n", nfailed);
					for (k = 0; k < nfailed; k++)
						fprintf(rp, "  %s\n", failed_names[k]);
					FreeFile(rp);
				}
			}
			elog(LOG, "pgfuzz: %d extra type(s) enabled", nextra);
		}
	}

	MemoryContextSwitchTo(oldctx);
	CommitTransactionCommand();

	return 0;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	sigjmp_buf	local_sigjmp_buf;
	MemoryContext ctx;
	MemoryContext oldctx;
	char	   *s;
	int			sel;
	FmgrInfo   *fn;
	Oid			ioparam;

	/*
	 * Per-iteration stack base for check_stack_depth(); see the long note in
	 * fuzz_util.h:pgfuzz_run().  FuzzerInitialize() -> InitStandaloneProcess()
	 * already recorded one, but on the initialization frame, which handed the
	 * guard a constant offset as extra budget and let runaway recursion reach
	 * the real stack limit instead of erroring out.
	 */
	set_stack_base();

	/*
	 * Take SIGALRM back from libFuzzer, once, HERE and not in
	 * LLVMFuzzerInitialize -- libFuzzer installs its handler after
	 * initialization returns, so reclaiming any earlier is the bug.
	 * See fuzz_timeout.h, whose own header named this target as one of the
	 * three with nothing bounding a single input, and then was included by
	 * exactly one of them.
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

	/*
	 * The selector spans the built-in variants and any workspace-configured
	 * extra types, so the fuzzer splits its budget across both. Extra types
	 * sit above the fixed ones, which keeps the selector byte stable for the
	 * built-ins: a corpus grown against one workspace stays meaningful on
	 * another that has none configured.
	 */
	sel = data[0] % (lengthof(variants) + nextra);
	data++;
	size--;

	if (sel < lengthof(variants))
	{
		if (!variants_ready[sel])
			return 0;
		fn = &flinfo[sel];
		ioparam = typioparam[sel];
	}
	else
	{
		fn = &extra_flinfo[sel - lengthof(variants)];
		ioparam = extra_typioparam[sel - lengthof(variants)];
	}

	s = (char *) malloc(size + 1);
	if (s == NULL)
		return 0;
	if (size > 0)
		memcpy(s, data, size);
	s[size] = '\0';

	ctx = AllocSetContextCreate(TopMemoryContext, "fuzz iteration",
								ALLOCSET_SMALL_SIZES);
	oldctx = MemoryContextSwitchTo(ctx);

	/*
	 * A transaction per input, as a real backend has per query.  These input
	 * functions reach the catalog -- regclassin and regtypein resolve names,
	 * aclitemin resolves roles, and array_in/range_in look up the element
	 * type's own input function -- and catcache.c asserts IsTransactionState().
	 */
	if (sigsetjmp(local_sigjmp_buf, 0) == 0)
	{
		PG_exception_stack = &local_sigjmp_buf;
		error_context_stack = NULL;

		StartTransactionCommand();
		pgfuzz_timeout_arm();
		(void) InputFunctionCall(fn, s, ioparam, -1);
		pgfuzz_timeout_disarm();
		CommitTransactionCommand();
	}
	else
	{
		/* the ERROR left a transaction open; a backend would abort it */
		pgfuzz_probe_show_error("backend_types_fuzzer");
		pgfuzz_timeout_disarm();
		AbortCurrentTransaction();
		MemoryContextSwitchTo(ctx);
		FlushErrorState();
	}

	PG_exception_stack = NULL;
	error_context_stack = NULL;

	MemoryContextSwitchTo(oldctx);
	MemoryContextDelete(ctx);
	free(s);

	/* See fuzz_canary.h: reachable-but-growing state is invisible to LSan. */
	pgfuzz_canary_check(data, size);
	return 0;
}

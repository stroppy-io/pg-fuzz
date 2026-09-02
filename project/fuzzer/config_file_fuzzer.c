/*-------------------------------------------------------------------------
 *
 * config_file_fuzzer.c
 *	  Fuzz postgresql.conf parsing.
 *
 * ParseConfigFp() is the recursive-descent parser behind postgresql.conf,
 * ALTER SYSTEM's postgresql.auto.conf, and include/include_if_exists
 * directives.  It is not client-facing, but postgresql.auto.conf is written
 * by ALTER SYSTEM from values a superuser supplies, and the parser runs at
 * every SIGHUP, so a hang or a crash here is a denial of service on reload.
 *
 * The config text is handed to the parser through fmemopen() so nothing
 * touches the filesystem.  elevel is LOG rather than ERROR: at ERROR the
 * parser longjmps out on the first syntax error and we would never reach the
 * code that handles a *partially* valid file.
 *
 *-------------------------------------------------------------------------
 */
#include "fuzz_util.h"
#include "fuzz_lineage.h"

#include "utils/guc.h"

#include <stdio.h>

static void
body(const char *s, size_t len, int sel)
{
	FILE	   *fp;
	ConfigVariable *head = NULL;
	ConfigVariable *tail = NULL;

	fp = fmemopen((void *) s, len, "r");
	if (fp == NULL)
		return;

	(void) ParseConfigFp(fp, "fuzz.conf", 0, LOG, &head, &tail);

	if (head != NULL)
		FreeConfigVariables(head);

	fclose(fp);

	/*
	 * The scalar value parsers are reached from SET as well as from the
	 * config file, with the value entirely under client control.
	 */
	{
		int			ival;
		double		dval;
		const char *hintmsg;

		(void) parse_int(s, &ival, 0, &hintmsg);
		(void) parse_int(s, &ival, GUC_UNIT_KB, &hintmsg);
		(void) parse_int(s, &ival, GUC_UNIT_MS, &hintmsg);
		(void) parse_real(s, &dval, 0, &hintmsg);
		(void) parse_real(s, &dval, GUC_UNIT_S, &hintmsg);
	}
}

int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
	pgfuzz_init();
	return 0;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (size == 0)
		return 0;
	pgfuzz_run(body, data, size, 0);
	return 0;
}

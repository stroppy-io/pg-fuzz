/*-------------------------------------------------------------------------
 *
 * hba_file_fuzzer.c
 *	  Fuzz pg_hba.conf and pg_ident.conf parsing.
 *
 * This is the file that decides who may connect and how they authenticate.
 * It is re-parsed on every SIGHUP, and a parse failure is meant to leave the
 * old rules in place -- so a crash in the parser is a denial of service, and a
 * parser bug that mis-assembles a rule is an authentication bypass.
 *
 * tokenize_auth_file() handles quoting, comments, continuations and @-file
 * inclusion; parse_hba_line() then interprets the token lists, including CIDR
 * masks and the authentication-option key/value pairs.  Address parsing uses
 * AI_NUMERICHOST, so the fuzzer generates no DNS traffic.
 *
 * The input goes through a real file rather than fmemopen(), because
 * tokenize_auth_file() is not a valid entry point on its own: it opens with
 * Assert(tokenize_context), and that context is created by open_auth_file()
 * (and destroyed by free_auth_file()).  Calling the tokenizer directly leaves
 * the static context NULL, so the first MemoryContextSwitchTo(tokenize_context)
 * makes CurrentMemoryContext NULL and palloc0() dereferences it.  Asserts are
 * compiled out here, so that surfaces as a SEGV in palloc0 that looks exactly
 * like a PostgreSQL bug and is not one.
 *
 * elevel is LOG so the parser reports and continues instead of longjmping out
 * on the first bad line.
 *
 *-------------------------------------------------------------------------
 */
#include "fuzz_util.h"
#include "fuzz_lineage.h"

#include "libpq/hba.h"
#include "nodes/pg_list.h"
#include "utils/conffiles.h"	/* CONF_FILE_START_DEPTH */

#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static char conf_dir[64];
static char conf_path[96];

static void
body(const char *s, size_t len, int sel)
{
	FILE	   *fp;
	List	   *tok_lines = NIL;
	ListCell   *lc;
	char	   *err_msg = NULL;

	fp = open_auth_file(conf_path, LOG, CONF_FILE_START_DEPTH, &err_msg);
	if (fp == NULL)
		return;

	tokenize_auth_file(conf_path, fp, &tok_lines, LOG, CONF_FILE_START_DEPTH);

	foreach(lc, tok_lines)
	{
		TokenizedAuthLine *tok_line = (TokenizedAuthLine *) lfirst(lc);

		if (tok_line->err_msg != NULL)
			continue;

		/*
		 * The same token lines feed both parsers: pg_hba.conf and
		 * pg_ident.conf share a tokenizer but interpret the fields completely
		 * differently, and both are worth covering.
		 */
		if (sel == 0)
			(void) parse_hba_line(tok_line, LOG);
		else
			(void) parse_ident_line(tok_line, LOG);
	}

	/* also releases tokenize_context */
	free_auth_file(fp, CONF_FILE_START_DEPTH);
}

int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
	pgfuzz_init();

	/*
	 * A private directory per process, not just a private file name.  Two
	 * reasons: -jobs=N workers must not overwrite each other's config, and
	 * pg_hba.conf supports `include_dir`, which reads *every* file in the
	 * named directory as an auth file.  With the config sitting in /tmp, an
	 * input containing `include_dir "."` walks the whole of /tmp and times out
	 * -- an artifact of where the harness put the file, not a parser bug.  In
	 * a real cluster the file lives in the data directory, so `include_dir "."`
	 * is bounded by design.
	 */
	snprintf(conf_dir, sizeof(conf_dir), "/tmp/pgfuzz_hba_%d", (int) getpid());
	mkdir(conf_dir, 0700);
	snprintf(conf_path, sizeof(conf_path), "%s/pg_hba.conf", conf_dir);
	return 0;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	int			sel = pgfuzz_select(&data, &size, 2);
	FILE	   *out;

	if (size == 0)
		return 0;

	out = fopen(conf_path, "wb");
	if (out == NULL)
		return 0;
	fwrite(data, 1, size, out);
	fclose(out);

	pgfuzz_run(body, data, size, sel);

	unlink(conf_path);
	return 0;
}

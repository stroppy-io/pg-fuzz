/*-------------------------------------------------------------------------
 *
 * raw_parser_fuzzer.c
 *	  Fuzz the SQL grammar: scan.l + gram.y, via raw_parser().
 *
 * This is the target the upstream OSS-Fuzz simple_query_fuzzer was presumably
 * meant to be.  That one calls raw_parser(query, RAW_PARSE_TYPE_NAME), which
 * parses *a type name* rather than a SQL statement, so the SQL grammar is
 * never reached.  Here the leading input byte selects the parse mode, so all
 * six -- including RAW_PARSE_DEFAULT, the one that parses actual statements --
 * get exercised.
 *
 * Raw parsing needs no catalog, so this runs standalone and fast, and it is
 * the highest-throughput way to hammer the lexer's string/escape/dollar-quote
 * handling and the grammar's error recovery.
 *
 *-------------------------------------------------------------------------
 */
#include "fuzz_util.h"
#include "fuzz_lineage.h"

#include "nodes/pg_list.h"
#include "parser/parser.h"

static const RawParseMode parse_modes[] = {
	RAW_PARSE_DEFAULT,
	RAW_PARSE_TYPE_NAME,
	RAW_PARSE_PLPGSQL_EXPR,
	RAW_PARSE_PLPGSQL_ASSIGN1,
	RAW_PARSE_PLPGSQL_ASSIGN2,
	RAW_PARSE_PLPGSQL_ASSIGN3,
};

static void
body(const char *s, size_t len, int sel)
{
	List	   *parsetree;

	parsetree = raw_parser(s, parse_modes[sel]);

	/*
	 * Walk the result so the node tree is actually touched rather than just
	 * built; list_length alone is enough to make the compiler keep it.
	 */
	if (parsetree != NIL)
		(void) list_length(parsetree);
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
	int			sel = pgfuzz_select(&data, &size, lengthof(parse_modes));

	pgfuzz_run(body, data, size, sel);
	return 0;
}

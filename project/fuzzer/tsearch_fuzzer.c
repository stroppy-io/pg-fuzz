/*-------------------------------------------------------------------------
 *
 * tsearch_fuzzer.c
 *	  Fuzz tsvector/tsquery input and matching.
 *
 * tsvector and tsquery both serialize into packed variable-length structures:
 * a tsvector is a sorted array of (offset, length) entries pointing into a
 * string pool, a tsquery is a postfix-ordered operator array plus a string
 * pool.  Both are parsed straight from client text, and the matching code
 * walks those offsets, so a parser that emits an inconsistent structure turns
 * into an out-of-bounds read at match time -- which is why this harness runs
 * the match as well as the parse.
 *
 * Note these are the *type* input functions, which parse the tsvector/tsquery
 * syntax directly; to_tsvector()/to_tsquery() need a text-search
 * configuration from the catalog and live in the backend harness.
 *
 *-------------------------------------------------------------------------
 */
#include "fuzz_util.h"
#include "fuzz_lineage.h"

#include "utils/fmgrprotos.h"

#define DEFAULT_VECTOR "'cat':1 'fat':2,4 'rat':3A 'sat':5B"
#define DEFAULT_QUERY  "cat & (fat | rat) & !sat"

static void
body(const char *s, size_t len, int sel)
{
	Datum		v;
	Datum		q;

	switch (sel)
	{
		case 0:
			v = DirectFunctionCall1(tsvectorin, CStringGetDatum(s));
			(void) DirectFunctionCall1(tsvectorout, v);
			(void) DirectFunctionCall1(tsvector_length, v);
			q = DirectFunctionCall1(tsqueryin, CStringGetDatum(DEFAULT_QUERY));
			(void) DirectFunctionCall2(ts_match_vq, v, q);
			break;

		case 1:
			q = DirectFunctionCall1(tsqueryin, CStringGetDatum(s));
			(void) DirectFunctionCall1(tsqueryout, q);
			(void) DirectFunctionCall1(tsquery_numnode, q);
			v = DirectFunctionCall1(tsvectorin, CStringGetDatum(DEFAULT_VECTOR));
			(void) DirectFunctionCall2(ts_match_vq, v, q);
			break;

		case 2:
			/* tsquery rewriting walks the operator array a second way */
			q = DirectFunctionCall1(tsqueryin, CStringGetDatum(s));
			/*
			 * tsquery_and/tsquery_or are the && and || operators and take TWO
			 * tsqueries; tsquery_not takes one.  Calling a two-argument
			 * function through DirectFunctionCall1 reads an uninitialised
			 * second argument, which is not a test of anything -- it trips
			 * Assert(in->valnode->type == QI_OPR) in tsquery_util.c on
			 * garbage.
			 */
			(void) DirectFunctionCall2(tsquery_and, q, q);
			(void) DirectFunctionCall2(tsquery_or, q, q);
			(void) DirectFunctionCall1(tsquery_not, q);
			break;

		default:
			/* concatenation reallocates and re-offsets both string pools */
			v = DirectFunctionCall1(tsvectorin, CStringGetDatum(s));
			(void) DirectFunctionCall2(tsvector_concat, v, v);
			break;
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
	int			sel = pgfuzz_select(&data, &size, 4);

	pgfuzz_run(body, data, size, sel);
	return 0;
}

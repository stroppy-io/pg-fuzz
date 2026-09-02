/*-------------------------------------------------------------------------
 *
 * jsonpath_fuzzer.c
 *	  Fuzz the SQL/JSON path language: parser, binary encoding, and executor.
 *
 * jsonpath has its own lexer and grammar (jsonpath_scan.l, jsonpath_gram.y)
 * and its own serialized form -- a tree of variable-length nodes with
 * internal byte offsets, built by flattenJsonPathParseItem().  Offsets
 * written by the encoder are followed by the executor, so a parser bug turns
 * directly into out-of-bounds reads during evaluation.
 *
 * Input format: "<jsonpath>\n<jsonb document>".  Without a newline the path
 * is evaluated against a small fixed document, so that the executor is
 * reached even when the fuzzer has not yet learned to produce two parts.
 *
 *-------------------------------------------------------------------------
 */
#include "fuzz_util.h"
#include "fuzz_lineage.h"

#include "utils/fmgrprotos.h"

#define DEFAULT_DOC "{\"a\":[1,2,{\"b\":\"x\"}],\"c\":{\"d\":null},\"e\":1.5}"

static void
body(const char *s, size_t len, int sel)
{
	const char *nl = strchr(s, '\n');
	char	   *path;
	const char *doc;
	size_t		plen;
	Datum		jp;
	Datum		jb;

	plen = nl ? (size_t) (nl - s) : strlen(s);
	doc = nl ? nl + 1 : DEFAULT_DOC;

	path = palloc(plen + 1);
	memcpy(path, s, plen);
	path[plen] = '\0';

	/* parse + serialize */
	jp = DirectFunctionCall1(jsonpath_in, CStringGetDatum(path));

	/* deserialize back to text: walks every offset the encoder wrote */
	(void) DirectFunctionCall1(jsonpath_out, jp);

	if (*doc == '\0')
		return;

	jb = DirectFunctionCall1(jsonb_in, CStringGetDatum(doc));

	/*
	 * Evaluate.  The _opr variants take (jsonb, jsonpath) and use the
	 * non-silent error mode, which is the path with the most code in it.
	 */
	switch (sel)
	{
		case 0:
			(void) DirectFunctionCall2(jsonb_path_exists_opr, jb, jp);
			break;
		case 1:
			(void) DirectFunctionCall2(jsonb_path_match_opr, jb, jp);
			break;
		default:
			(void) DirectFunctionCall2(jsonb_path_exists_opr, jb, jp);
			(void) DirectFunctionCall2(jsonb_path_match_opr, jb, jp);
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
	int			sel = pgfuzz_select(&data, &size, 3);

	pgfuzz_run(body, data, size, sel);
	return 0;
}

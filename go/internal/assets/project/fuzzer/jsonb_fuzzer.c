/*-------------------------------------------------------------------------
 *
 * jsonb_fuzzer.c
 *	  Fuzz json and jsonb text input, and the jsonb binary representation.
 *
 * The upstream json_parser_fuzzer only drives pg_parse_json(), the pure
 * lexer/parser.  jsonb_in goes further: it builds the packed JsonbValue tree,
 * sorts and de-duplicates object keys, and encodes everything into the
 * on-disk jsonb container format with its JEntry offset/length arithmetic.
 * That encoder is where the interesting memory-safety surface is, and it is
 * only reachable through jsonb_in, not through pg_parse_json.
 *
 *-------------------------------------------------------------------------
 */
#include "fuzz_util.h"
#include "fuzz_lineage.h"

#include "utils/fmgrprotos.h"

static void
body(const char *s, size_t len, int sel)
{
	Datum		d;

	switch (sel)
	{
		case 0:
			/* json: validate-and-store, keeps the original text */
			d = DirectFunctionCall1(json_in, CStringGetDatum(s));
			(void) DirectFunctionCall1(json_out, d);
			(void) DirectFunctionCall1(json_typeof, d);
			break;

		case 1:
			/* jsonb: full parse into the binary container format */
			d = DirectFunctionCall1(jsonb_in, CStringGetDatum(s));
			(void) DirectFunctionCall1(jsonb_out, d);
			break;

		case 2:
			/* re-walk the container: exercises the JEntry decoding path */
			d = DirectFunctionCall1(jsonb_in, CStringGetDatum(s));
			(void) DirectFunctionCall1(jsonb_typeof, d);
			(void) DirectFunctionCall1(jsonb_strip_nulls, d);
			(void) DirectFunctionCall1(jsonb_pretty, d);
			break;

		case 3:
			/* text -> jsonb -> text round trip through the output encoder */
			d = DirectFunctionCall1(jsonb_in, CStringGetDatum(s));
			d = DirectFunctionCall1(jsonb_out, d);
			(void) DirectFunctionCall1(jsonb_in, d);
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

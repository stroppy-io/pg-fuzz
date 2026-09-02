/*-------------------------------------------------------------------------
 *
 * formatting_fuzzer.c
 *	  Fuzz to_date() / to_timestamp() / to_number() format-string handling.
 *
 * formatting.c is the single most alarming parser in the backend: it compiles
 * a user-supplied format string ('YYYY-MM-DD', 'FMDay', '9G999D99') into a
 * node array and then walks the value against it, with a lot of manual
 * pointer arithmetic and fixed-size buffers.  Both the format string *and*
 * the value come from the client, which is why this gets its own target
 * instead of riding along in datetime_fuzzer.
 *
 * Input format: "<value>\n<format>".  Without a newline the whole input is
 * used as the format string against a fixed value, which is the direction
 * that historically breaks.
 *
 *-------------------------------------------------------------------------
 */
#include "fuzz_util.h"
#include "fuzz_lineage.h"

#include "utils/builtins.h"		/* CStringGetTextDatum */
#include "utils/fmgrprotos.h"

static const PGFunction parsers[] = {
	to_date,					/* to_date(text, text) */
	to_timestamp,				/* to_timestamp(text, text) */
	numeric_to_number,			/* to_number(text, text) */
};

static void
body(const char *s, size_t len, int sel)
{
	const char *nl = strchr(s, '\n');
	char	   *value;
	const char *format;
	size_t		vlen;

	if (nl != NULL)
	{
		vlen = (size_t) (nl - s);
		format = nl + 1;
	}
	else
	{
		/* no separator: fuzz the format string against a plausible value */
		vlen = 0;
		format = s;
	}

	value = palloc(vlen + 1);
	if (vlen > 0)
		memcpy(value, s, vlen);
	else
		strcpy(value, "2024-01-02 03:04:05");
	value[vlen] = '\0';

	(void) DirectFunctionCall2(parsers[sel % lengthof(parsers)],
							   CStringGetTextDatum(value),
							   CStringGetTextDatum(format));
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
	int			sel = pgfuzz_select(&data, &size, lengthof(parsers));

	pgfuzz_run(body, data, size, sel);
	return 0;
}

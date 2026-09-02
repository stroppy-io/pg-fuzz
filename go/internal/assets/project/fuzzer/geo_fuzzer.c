/*-------------------------------------------------------------------------
 *
 * geo_fuzzer.c
 *	  Fuzz the geometric type input functions.
 *
 * path_in and poly_in read a client-supplied point count and then allocate
 * and fill a variable-length structure from it -- the classic shape of a
 * heap overflow.  The rest (point, box, lseg, line, circle) are simpler but
 * share the same hand-written token scanner in geo_ops.c.
 *
 *-------------------------------------------------------------------------
 */
#include "fuzz_util.h"
#include "fuzz_lineage.h"

#include "utils/fmgrprotos.h"

typedef struct
{
	const char *name;
	PGFunction	fn;
} io_entry;

static const io_entry types[] = {
	{"point", point_in},
	{"lseg", lseg_in},
	{"line", line_in},
	{"box", box_in},
	{"path", path_in},
	{"polygon", poly_in},
	{"circle", circle_in},
};

static void
body(const char *s, size_t len, int sel)
{
	const io_entry *e = &types[sel];
	Datum		d;

	d = DirectFunctionCall1(e->fn, CStringGetDatum(s));

	/*
	 * Round-trip through the output function: the *_out routines re-walk the
	 * structure the *_in routine built, so a bad point count that survived
	 * parsing tends to blow up here.
	 */
	switch (sel)
	{
		case 0:
			(void) DirectFunctionCall1(point_out, d);
			break;
		case 1:
			(void) DirectFunctionCall1(lseg_out, d);
			break;
		case 2:
			(void) DirectFunctionCall1(line_out, d);
			break;
		case 3:
			(void) DirectFunctionCall1(box_out, d);
			break;
		case 4:
			(void) DirectFunctionCall1(path_out, d);
			break;
		case 5:
			(void) DirectFunctionCall1(poly_out, d);
			break;
		case 6:
			(void) DirectFunctionCall1(circle_out, d);
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
	int			sel = pgfuzz_select(&data, &size, lengthof(types));

	pgfuzz_run(body, data, size, sel);
	return 0;
}

/*-------------------------------------------------------------------------
 *
 * datetime_fuzzer.c
 *	  Fuzz date/time input parsing.
 *
 * datetime.c's DecodeDateTime()/DecodeInterval() are a hand-written tokenizer
 * over a table of keywords, special-cased for a dozen DateStyle and
 * IntervalStyle combinations, operating on fixed-size on-stack arrays.  It has
 * a long history of overflow bugs.  The leading input byte selects both the
 * type and the DateStyle, because the parse path differs substantially
 * between styles (ISO vs. SQL vs. German ordering changes which field is read
 * as which).
 *
 * session_timezone is set to GMT by pgfuzz_init() -- timetz_in and
 * timestamptz_in dereference it unconditionally.
 *
 *-------------------------------------------------------------------------
 */
#include "fuzz_util.h"
#include "fuzz_lineage.h"

#include "utils/datetime.h"
#include "utils/fmgrprotos.h"

typedef struct
{
	const char *name;
	PGFunction	fn;
	bool		three_args;
} io_entry;

static const io_entry types[] = {
	{"date", date_in, false},
	{"time", time_in, true},
	{"timetz", timetz_in, true},
	{"timestamp", timestamp_in, true},
	{"timestamptz", timestamptz_in, true},
	{"interval", interval_in, true},
};

static const int date_styles[] = {USE_ISO_DATES, USE_POSTGRES_DATES,
	USE_SQL_DATES, USE_GERMAN_DATES};

static const int date_orders[] = {DATEORDER_YMD, DATEORDER_DMY, DATEORDER_MDY};

static void
body(const char *s, size_t len, int sel)
{
	const io_entry *e = &types[sel % lengthof(types)];
	int			v = sel / lengthof(types);

	/*
	 * DateStyle/DateOrder are plain globals; setting them directly avoids
	 * going through the GUC machinery on every iteration.
	 */
	DateStyle = date_styles[v % lengthof(date_styles)];
	DateOrder = date_orders[(v / lengthof(date_styles)) % lengthof(date_orders)];

	(void) pgfuzz_call_in(e->fn, e->three_args, s, InvalidOid);
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
	int			sel = pgfuzz_select(&data, &size, 256);

	pgfuzz_run(body, data, size, sel);
	return 0;
}

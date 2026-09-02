/*-------------------------------------------------------------------------
 *
 * scalar_types_fuzzer.c
 *	  Fuzz the text input functions of PostgreSQL's built-in scalar types.
 *
 * Type input functions parse text that came straight from a client, so they
 * are one of the largest untrusted-input surfaces in the backend.  The
 * leading input byte picks which type to parse as; the rest is the value.
 *
 * Only catalog-free types are listed here.  aclitemin and the reg* input
 * functions resolve names through the catalog and belong in the
 * backend-initialized harness (backend_types_fuzzer.c); calling them without
 * a backend would crash on catalog access and waste triage time.
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
	bool		three_args;
} io_entry;

static const io_entry types[] = {
	{"bool", boolin, false},
	{"int2", int2in, false},
	{"int4", int4in, false},
	{"int8", int8in, false},
	{"float4", float4in, false},
	{"float8", float8in, false},
	{"oid", oidin, false},
	{"xid", xidin, false},
	{"xid8", xid8in, false},
	{"tid", tidin, false},
	{"cid", cidin, false},
	{"pg_lsn", pg_lsn_in, false},
	{"bytea", byteain, false},
	{"text", textin, false},
	{"name", namein, false},
	{"char", charin, false},
	{"uuid", uuid_in, false},
	{"money", cash_in, false},
	{"int2vector", int2vectorin, false},
	{"oidvector", oidvectorin, false},
	{"pg_snapshot", pg_snapshot_in, false},
	/* typmod-taking input functions */
	{"bpchar", bpcharin, true},
	{"varchar", varcharin, true},
	{"bit", bit_in, true},
	{"varbit", varbit_in, true},
};

static void
body(const char *s, size_t len, int sel)
{
	const io_entry *e = &types[sel];

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
	int			sel = pgfuzz_select(&data, &size, lengthof(types));

	pgfuzz_run(body, data, size, sel);
	return 0;
}

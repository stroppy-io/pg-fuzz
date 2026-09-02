/*-------------------------------------------------------------------------
 *
 * binary_recv_fuzzer.c
 *	  Fuzz the binary-format receive functions of the built-in types.
 *
 * This is, target for target, the most promising surface in this workspace.
 * Every type has a *_recv(internal) function that decodes the *binary* wire
 * format, reached whenever a client sends a parameter with format code 1 in
 * the extended query protocol, or via COPY BINARY.  Unlike the text input
 * functions, these read raw length fields and offsets out of the message and
 * are far less exercised by the regression tests -- a length field read with
 * pq_getmsgint() and then used as an allocation size or a loop bound is the
 * standard shape here.
 *
 * The whole input becomes the StringInfo message body, so the fuzzer has
 * direct control over every byte the decoder reads.
 *
 * Container receive functions are deliberately absent: array_recv, record_recv,
 * range_recv and the reg* ones look the element type's own receive function up
 * in pg_type, which needs a live backend.  So do int2vectorrecv and
 * oidvectorrecv, which are not obviously containers but delegate to array_recv
 * internally -- they crashed this harness in SearchCatCacheInternal within
 * seconds.  They live in backend_types_fuzzer.c instead.
 *
 *-------------------------------------------------------------------------
 */
#include "fuzz_util.h"
#include "fuzz_lineage.h"

#include "lib/stringinfo.h"
#include "libpq/pqformat.h"
#include "utils/fmgrprotos.h"

typedef struct
{
	const char *name;
	PGFunction	fn;
	bool		three_args;
} recv_entry;

static const recv_entry types[] = {
	{"bool", boolrecv, false},
	{"bytea", bytearecv, false},
	{"char", charrecv, false},
	{"name", namerecv, false},
	{"text", textrecv, false},
	{"cstring", cstring_recv, false},
	{"unknown", unknownrecv, false},
	{"int2", int2recv, false},
	{"int4", int4recv, false},
	{"int8", int8recv, false},
	{"float4", float4recv, false},
	{"float8", float8recv, false},
	{"oid", oidrecv, false},
	{"xid", xidrecv, false},
	{"xid8", xid8recv, false},
	{"cid", cidrecv, false},
	{"tid", tidrecv, false},
	{"pg_lsn", pg_lsn_recv, false},
	{"money", cash_recv, false},
	{"uuid", uuid_recv, false},
	{"date", date_recv, false},
	{"pg_snapshot", pg_snapshot_recv, false},
	{"pg_node_tree", pg_node_tree_recv, false},
	{"point", point_recv, false},
	{"lseg", lseg_recv, false},
	{"line", line_recv, false},
	{"box", box_recv, false},
	{"path", path_recv, false},
	{"polygon", poly_recv, false},
	{"circle", circle_recv, false},
	{"inet", inet_recv, false},
	{"cidr", cidr_recv, false},
	{"macaddr", macaddr_recv, false},
	{"macaddr8", macaddr8_recv, false},
	{"json", json_recv, false},
	{"jsonb", jsonb_recv, false},
	{"jsonpath", jsonpath_recv, false},
	{"tsvector", tsvectorrecv, false},
	{"tsquery", tsqueryrecv, false},
	/* typmod-taking receive functions */
	{"bpchar", bpcharrecv, true},
	{"varchar", varcharrecv, true},
	{"bit", bit_recv, true},
	{"varbit", varbit_recv, true},
	{"numeric", numeric_recv, true},
	{"time", time_recv, true},
	{"timetz", timetz_recv, true},
	{"timestamp", timestamp_recv, true},
	{"timestamptz", timestamptz_recv, true},
	{"interval", interval_recv, true},
};

static void
body(const char *s, size_t len, int sel)
{
	const recv_entry *e = &types[sel];
	StringInfoData buf;

	/*
	 * pq_getmsgend() -- which most recv functions call -- errors out unless
	 * the whole message was consumed, so we do not append anything of our
	 * own; the input is the message.
	 */
	initStringInfo(&buf);
	appendBinaryStringInfo(&buf, s, (int) len);

	if (e->three_args)
		(void) DirectFunctionCall3(e->fn,
								   PointerGetDatum(&buf),
								   ObjectIdGetDatum(InvalidOid),
								   Int32GetDatum(-1));
	else
		(void) DirectFunctionCall1(e->fn, PointerGetDatum(&buf));
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

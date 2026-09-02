/*-------------------------------------------------------------------------
 *
 * network_fuzzer.c
 *	  Fuzz inet/cidr/macaddr input parsing and the inet operators.
 *
 * inet_in parses both IPv4 and IPv6 text, including the netmask suffix, into
 * a packed structure whose length field is derived from the parsed family.
 * inet_net_pton() underneath is a BIND-derived routine that writes into a
 * caller-supplied buffer sized from that family -- worth watching under ASan.
 *
 *-------------------------------------------------------------------------
 */
#include "fuzz_util.h"
#include "fuzz_lineage.h"

#include "utils/fmgrprotos.h"

typedef struct
{
	const char *name;
	PGFunction	in;
	PGFunction	out;
} io_entry;

static const io_entry types[] = {
	{"inet", inet_in, inet_out},
	{"cidr", cidr_in, cidr_out},
	{"macaddr", macaddr_in, macaddr_out},
	{"macaddr8", macaddr8_in, macaddr8_out},
};

static void
body(const char *s, size_t len, int sel)
{
	const io_entry *e = &types[sel % lengthof(types)];
	Datum		d;

	d = DirectFunctionCall1(e->in, CStringGetDatum(s));
	(void) DirectFunctionCall1(e->out, d);

	/* inet/cidr carry extra structure-walking helpers worth reaching */
	if (sel < 2)
	{
		(void) DirectFunctionCall1(network_host, d);
		(void) DirectFunctionCall1(network_broadcast, d);
		(void) DirectFunctionCall1(network_network, d);
		(void) DirectFunctionCall1(network_netmask, d);
		(void) DirectFunctionCall1(sel == 0 ? inet_abbrev : cidr_abbrev, d);
		(void) DirectFunctionCall1(network_family, d);
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

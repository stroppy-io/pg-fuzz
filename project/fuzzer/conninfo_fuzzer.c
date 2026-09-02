/*-------------------------------------------------------------------------
 *
 * conninfo_fuzzer.c
 *	  Fuzz libpq's connection string and URI parser.
 *
 * This is the only *client-side* target in the workspace, and it is linked
 * against libpq rather than the backend.  PQconninfoParse() handles both the
 * keyword/value form ("host=x port=5432") and the URI form
 * ("postgresql://user:pw@host:5432/db?opt=v"), including percent-decoding,
 * backslash escapes and quoted values.  Connection strings routinely come
 * from places the application does not fully control -- config files,
 * environment, service files, web UIs -- so a memory-safety bug here is
 * reachable in real deployments.
 *
 * Unlike the backend harnesses this needs no PostgreSQL runtime at all, so it
 * is compiled and linked separately in build.sh.
 *
 *-------------------------------------------------------------------------
 */
#include "postgres_fe.h"

#include "libpq-fe.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "fuzz_lineage.h"

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	char	   *s;
	char	   *errmsg = NULL;
	PQconninfoOption *opts;

	s = (char *) malloc(size + 1);
	if (s == NULL)
		return 0;
	if (size > 0)
		memcpy(s, data, size);
	s[size] = '\0';

	opts = PQconninfoParse(s, &errmsg);
	if (opts != NULL)
		PQconninfoFree(opts);
	if (errmsg != NULL)
		PQfreemem(errmsg);

	/*
	 * The connection-less quoting helpers take untrusted text too, and are
	 * what applications are told to use to build safe SQL.  (The *Conn
	 * variants need a live PGconn, so they are out of reach here.)
	 */
	{
		char	   *quoted = (char *) malloc(2 * size + 1);
		size_t		blen = 0;
		unsigned char *bytea;

		if (quoted != NULL)
		{
			(void) PQescapeString(quoted, s, size);
			free(quoted);
		}

		bytea = PQescapeBytea((const unsigned char *) s, size, &blen);
		if (bytea != NULL)
			PQfreemem(bytea);
	}

	free(s);
	return 0;
}

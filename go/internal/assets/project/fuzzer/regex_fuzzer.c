/*-------------------------------------------------------------------------
 *
 * regex_fuzzer.c
 *	  Fuzz PostgreSQL's regular expression engine.
 *
 * src/backend/regex is Henry Spencer's engine, substantially modified.  It
 * compiles a pattern into an NFA, optionally determinizes it, and runs a
 * backtracking matcher over pg_wchar.  Patterns come from clients (LIKE,
 * SIMILAR TO, ~, regexp_replace) and the compiler does a lot of graph
 * surgery, so both compile-time and match-time bugs are reachable remotely.
 *
 * The collation is pinned to C_COLLATION_OID: it makes lc_ctype_is_c() true
 * without a catalog lookup, so the harness stays standalone.
 *
 * Input format: "<pattern>\n<subject>".
 *
 *-------------------------------------------------------------------------
 */
#include "fuzz_util.h"

#include "catalog/pg_collation.h"
#include "mb/pg_wchar.h"
#include "regex/regex.h"
#include "fuzz_deadline.h"
#include "fuzz_lineage.h"

#define DEFAULT_SUBJECT "abcABC123 the quick brown fox"

/*
 * Compiling a pathological pattern is superlinear by design (that is what a
 * regex engine does), so keep patterns short enough that the fuzzer explores
 * many of them rather than sitting in one.  libFuzzer's -timeout still
 * catches the genuine runaways.
 */
#define MAX_PATTERN_LEN 256

static const int cflag_sets[] = {
	REG_ADVANCED,
	REG_ADVANCED | REG_ICASE,
	REG_ADVANCED | REG_NEWLINE,
	REG_EXTENDED,
	REG_BASIC,
	REG_QUOTE,
	REG_ADVANCED | REG_EXPANDED,
	REG_ADVANCED | REG_NOSUB,
};

static void
body(const char *s, size_t len, int sel)
{
	const char *nl = strchr(s, '\n');
	size_t		plen;
	const char *subject;
	pg_wchar   *wpat;
	pg_wchar   *wsub;
	int			wpatlen;
	int			wsublen;
	size_t		sublen;
	regex_t		re;
	int			err;
	regmatch_t	pmatch[10];

	plen = nl ? (size_t) (nl - s) : strlen(s);
	if (plen > MAX_PATTERN_LEN)
		plen = MAX_PATTERN_LEN;

	subject = nl ? nl + 1 : DEFAULT_SUBJECT;
	sublen = strlen(subject);

	wpat = (pg_wchar *) palloc((plen + 1) * sizeof(pg_wchar));
	wpatlen = pg_mb2wchar_with_len(s, wpat, (int) plen);

	err = pg_regcomp(&re, wpat, wpatlen, cflag_sets[sel], C_COLLATION_OID);
	if (err != 0)
		return;					/* invalid pattern: not a finding */

	wsub = (pg_wchar *) palloc((sublen + 1) * sizeof(pg_wchar));
	wsublen = pg_mb2wchar_with_len(subject, wsub, (int) sublen);

	/*
	 * Catastrophic backtracking is the point of fuzzing this, and it is
	 * unbounded: one input ran 443 s against a 90 s budget. The engine calls
	 * INTERRUPT(re) -> CHECK_FOR_INTERRUPTS() (regcustom.h:55), so a deadline
	 * that sets the cancel flags stops it, and pgfuzz_run()'s sigsetjmp
	 * catches the resulting error like any other.
	 */
	pgfuzz_deadline_arm();
	(void) pg_regexec(&re, wsub, wsublen, 0, NULL,
					  lengthof(pmatch), pmatch, 0);
	pgfuzz_deadline_disarm();

	/*
	 * pg_regprefix walks the compiled NFA looking for a fixed prefix; it is a
	 * separate traversal of the same graph and has had its own bugs.
	 */
	{
		pg_wchar   *prefix = NULL;
		size_t		prefixlen = 0;

		if (pg_regprefix(&re, &prefix, &prefixlen) >= 0 && prefix != NULL)
			pfree(prefix);
	}

	pg_regfree(&re);
}

int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
	pgfuzz_deadline_init();
	pgfuzz_init();
	return 0;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	int			sel = pgfuzz_select(&data, &size, lengthof(cflag_sets));

	pgfuzz_run(body, data, size, sel);
	return 0;
}

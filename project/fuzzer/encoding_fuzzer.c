/*-------------------------------------------------------------------------
 *
 * encoding_fuzzer.c
 *	  Fuzz the multibyte encoding validation and conversion routines.
 *
 * src/common/wchar.c is reached before authentication: the startup packet,
 * the user name, the database name and every subsequent query string are run
 * through pg_verify_mbstr_len() and friends.  Each supported server encoding
 * has its own hand-written mblen/verify/mb2wchar routine, several of which do
 * lookahead past the byte they were handed, so truncated multibyte sequences
 * at a buffer boundary are exactly what we want to generate here.
 *
 * The leading input byte selects the encoding, so all of them get covered
 * rather than just UTF-8.
 *
 *-------------------------------------------------------------------------
 */
#include "fuzz_util.h"
#include "fuzz_lineage.h"

#include "mb/pg_wchar.h"

static void
body(const char *s, size_t len, int sel)
{
	int			encoding = sel;
	int			maxlen;
	pg_wchar   *wbuf;
	char	   *mbbuf;
	int			nwchars;
	int			i;

	if (!PG_VALID_ENCODING(encoding) || !pg_valid_server_encoding_id(encoding))
		return;

	maxlen = pg_encoding_max_length(encoding);

	/* validation: the pre-authentication path */
	(void) pg_encoding_verifymbstr(encoding, s, (int) len);
	(void) pg_verify_mbstr_len(encoding, s, (int) len, true);

	/* per-character length, including the truncated-tail cases */
	for (i = 0; i < (int) len;)
	{
		int			clen = pg_encoding_verifymbchar(encoding, s + i, (int) len - i);

		if (clen < 0)
			break;
		(void) pg_encoding_mblen_bounded(encoding, s + i);
		(void) pg_encoding_dsplen(encoding, s + i);
		i += clen > 0 ? clen : 1;
	}

	/* clipping: used when truncating identifiers and error messages */
	(void) pg_encoding_mbcliplen(encoding, s, (int) len, (int) len / 2);

	/*
	 * Round trip through the wide-character form, with the output buffer sized
	 * exactly the way PostgreSQL sizes it -- per encoding, as regexp.c does
	 * with pg_database_encoding_max_length() * slen + 1.
	 *
	 * This reports a heap overflow for EUC_CN, and that report is kept rather
	 * than engineered away.  EUC_CN has a max length of 2 but shares
	 * pg_euc2wchar_with_len with EUC_JP, which packs an SS3 sequence into
	 * *three* bytes ((SS3 << 16) | (b2 << 8) | b3); pg_wchar2euc_with_len then
	 * writes three bytes back.  Whether that is reachable is a question about
	 * PostgreSQL -- it turns on whether unvalidated bytes can reach these
	 * converters -- and the place to answer it is a triage record with
	 * evidence, not a buffer quietly enlarged here.  Enlarging it to
	 * MAX_MULTIBYTE_CHAR_LEN, or skipping input the encoding rejects, silences
	 * this case *and* every reachable case of the same shape.
	 *
	 * See the workspace work log for the current verdict.
	 */
	wbuf = (pg_wchar *) palloc((len + 1) * sizeof(pg_wchar));
	nwchars = pg_encoding_mb2wchar_with_len(encoding, s, wbuf, (int) len);

	mbbuf = (char *) palloc((size_t) nwchars * (size_t) maxlen + 1);
	(void) pg_encoding_wchar2mb_with_len(encoding, wbuf, mbbuf, nwchars);
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
	/* one selector value per encoding id, valid or not */
	int			sel = pgfuzz_select(&data, &size, PG_ENCODING_BE_LAST + 1);

	pgfuzz_run(body, data, size, sel);
	return 0;
}

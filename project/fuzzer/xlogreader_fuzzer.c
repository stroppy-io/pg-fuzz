/*-------------------------------------------------------------------------
 *
 * xlogreader_fuzzer.c
 *	  Fuzz WAL record decoding (DecodeXLogRecord).
 *
 * A WAL record is a header followed by a chain of length-prefixed block
 * references and data chunks.  DecodeXLogRecord() walks that chain, and every
 * length it follows comes out of the record itself.  This matters beyond
 * crash recovery: a standby decodes WAL streamed from a primary, pg_waldump
 * and pg_rewind decode files handed to them, and logical decoding plugins
 * consume the result -- so the input is not always as trusted as "our own
 * WAL" suggests.
 *
 * Feeding whole WAL *segments* through XLogReadRecord() would be a waste of
 * fuzzing budget: page headers would reject essentially every mutation before
 * reaching the decoder.  So the record is built here and handed to
 * DecodeXLogRecord() directly -- but with a *valid* CRC, computed exactly the
 * way ValidXLogRecord() checks it.
 *
 * The CRC matters for whether a crash here is reportable at all, and the answer
 * turns on what a CRC is.  xl_crc is CRC32C: a plain, unkeyed checksum computed
 * by public code (xloginsert.c).  It is not an HMAC.  It detects accidental
 * corruption -- bit rot, a torn write -- and provides no authentication
 * whatsoever: anyone who can write the bytes can compute the matching CRC as
 * easily as PostgreSQL does.  There is also no GUC to skip it
 * (ignore_checksum_failure is for data pages), but that is beside the point,
 * because it never has to be skipped -- only recomputed.
 *
 * So "the CRC gate would have rejected this" is not a defence for the decoder.
 * A standby replaying from a compromised primary, pg_waldump or pg_rewind on an
 * untrusted file, a poisoned archive -- in every one the attacker controls the
 * bytes and can make the CRC agree.  Setting a real CRC here removes the
 * argument: whatever the decoder does with this record, it would do with a
 * record that passes the real check.
 *
 * DecodeXLogRecord clearly intends to be robust against a malformed record --
 * it has a shortdata_err path and reports "record with invalid length" -- so an
 * out-of-bounds read is a hole in that validation, not a caller contract
 * violation.
 *
 *-------------------------------------------------------------------------
 */
#include "fuzz_util.h"
#include "fuzz_lineage.h"

#include "access/xlog_internal.h"
#include "access/xlogreader.h"
#include "access/xlogrecord.h"
#include "port/pg_crc32c.h"

#include <stddef.h>				/* offsetof */

/*
 * Set xl_crc so the record passes ValidXLogRecord(), byte for byte the same
 * computation (xlogreader.c): body first, then the header up to xl_crc.
 */
static void
set_valid_crc(XLogRecord *record)
{
	pg_crc32c	crc;

	INIT_CRC32C(crc);
	COMP_CRC32C(crc, ((char *) record) + SizeOfXLogRecord,
				record->xl_tot_len - SizeOfXLogRecord);
	COMP_CRC32C(crc, (char *) record, offsetof(XLogRecord, xl_crc));
	FIN_CRC32C(crc);
	record->xl_crc = crc;
}

/* Recompute independently and confirm -- proof, not assumption. */
static bool
crc_is_valid(XLogRecord *record)
{
	pg_crc32c	crc;

	INIT_CRC32C(crc);
	COMP_CRC32C(crc, ((char *) record) + SizeOfXLogRecord,
				record->xl_tot_len - SizeOfXLogRecord);
	COMP_CRC32C(crc, (char *) record, offsetof(XLogRecord, xl_crc));
	FIN_CRC32C(crc);
	return EQ_CRC32C(record->xl_crc, crc);
}

static XLogReaderState *reader = NULL;

/* the reader needs a routine struct, but decoding never calls back into it */
static int
dummy_page_read(XLogReaderState *state, XLogRecPtr targetPagePtr, int reqLen,
				XLogRecPtr targetRecPtr, char *readBuf)
{
	return -1;
}

static void
dummy_segment_open(XLogReaderState *state, XLogSegNo nextSegNo,
				   TimeLineID *tli_p)
{
}

static void
dummy_segment_close(XLogReaderState *state)
{
}

static void
body(const char *s, size_t len, int sel)
{
	XLogRecord *record;
	DecodedXLogRecord *decoded;
	char	   *errormsg = NULL;
	size_t		space;

	if (len < SizeOfXLogRecord)
		return;

	/*
	 * Copy into palloc'd (MAXALIGN'd) memory: the decoder assumes the record
	 * is aligned and will read past "len" if xl_tot_len says so, which is
	 * precisely the bug class we are looking for -- so the buffer is sized to
	 * exactly xl_tot_len and ASan guards the far end.
	 */
	record = (XLogRecord *) palloc(len);
	memcpy(record, s, len);

	/*
	 * Make xl_tot_len agree with the buffer we actually have.  Leaving it
	 * fuzzer-controlled would just exercise the length sanity check at the
	 * top of the decoder over and over; pinning it means every input gets
	 * past that check and into the block-reference loop.
	 */
	record->xl_tot_len = (uint32) len;

	/*
	 * Make the record CRC-valid before decoding.  Without this, every crash
	 * found here invites "recovery would have rejected that at the CRC check"
	 * -- and roughly 41 artifacts per campaign were dismissed on exactly that
	 * argument.  With it, the record passes the same test ValidXLogRecord()
	 * applies, so any crash is reachable by anyone who can supply WAL bytes.
	 */
	set_valid_crc(record);
	if (!crc_is_valid(record))
		return;					/* cannot happen; belt and braces */

	space = DecodeXLogRecordRequiredSpace(record->xl_tot_len);
	decoded = (DecodedXLogRecord *) palloc(space);

	if (DecodeXLogRecord(reader, decoded, record, (XLogRecPtr) 0x1000000,
						 &errormsg))
	{
		int			block_id;

		/* walk what the decoder produced, the way a consumer would */
		for (block_id = 0; block_id <= decoded->max_block_id; block_id++)
		{
			DecodedBkpBlock *blk = &decoded->blocks[block_id];

			if (!blk->in_use)
				continue;
			(void) blk->data_len;
			(void) blk->bimg_len;
		}
	}
}

int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
	pgfuzz_init();

	reader = XLogReaderAllocate(DEFAULT_XLOG_SEG_SIZE, NULL,
								XL_ROUTINE(.page_read = dummy_page_read,
										   .segment_open = dummy_segment_open,
										   .segment_close = dummy_segment_close),
								NULL);
	return 0;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (reader == NULL)
		return 0;
	pgfuzz_run(body, data, size, 0);
	return 0;
}

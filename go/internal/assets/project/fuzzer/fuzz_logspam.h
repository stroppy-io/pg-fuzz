/*-------------------------------------------------------------------------
 * fuzz_logspam.h -- rate-limit repetitive server log messages
 *
 * WHY
 *
 * A fuzz target that feeds garbage to a protocol gets the same complaint back
 * for almost every input. protocol_fuzzer produced 51% of a slice log as one
 * line -- `FATAL: terminating connection because protocol synchronization was
 * lost` -- because desync IS the expected outcome of the thing it exists to
 * test. Every gate that greps a slice log paid for those bytes.
 *
 * WHY NOT log_min_messages
 *
 * The only GUC that suppresses a FATAL is log_min_messages=PANIC, and that
 * also discards ERROR -- the context immediately before a crash, which is what
 * triage reads. Trading a diagnostic for disk is the mistake this project keeps
 * making, so it is not on offer here.
 *
 * emit_log_hook is the supported mechanism for exactly this. elog.c calls it
 * ahead of every log destination, a hook may turn off edata->output_to_server,
 * and PostgreSQL's own comment describes it as "intended for custom log
 * filtering". It also passes message_id, the ORIGINAL English format string,
 * which is a stable identity for a message across locales and across the
 * varying parameters a fuzzer produces.
 *
 * WHAT THIS DOES
 *
 * It is deliberately NOT a list of known-noisy messages. The next message that
 * floods a log will not be one we thought of, so the rule is general: any
 * message repeated beyond a threshold is throttled, and everything else passes
 * through untouched.
 *
 *   - the first LOUD occurrences of a message go to the log verbatim;
 *   - after that one in every EVERY is let through, so the message never
 *     vanishes entirely and its rate stays visible;
 *   - the rest are suppressed, and a running count is reported on stderr so the
 *     volume remains a NUMBER rather than becoming silence. A reader must never
 *     have to infer from absence.
 *
 * PANIC is never throttled. Neither is anything a sanitizer or an assertion
 * produces, because those do not travel through elog at all.
 *
 * PGFUZZ_LOG_ALL=1 disables throttling, for when the repetition is the thing
 * being investigated.
 *-------------------------------------------------------------------------
 */
#ifndef FUZZ_LOGSPAM_H
#define FUZZ_LOGSPAM_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "utils/elog.h"

#define PGFUZZ_LOGSPAM_SLOTS  128
#define PGFUZZ_LOGSPAM_LOUD   5
#define PGFUZZ_LOGSPAM_EVERY  10000

typedef struct pgfuzz_logspam_slot
{
	unsigned int  hash;
	unsigned long seen;
	unsigned long suppressed;
	char          sample[72];
} pgfuzz_logspam_slot;

static pgfuzz_logspam_slot pgfuzz_logspam_tab[PGFUZZ_LOGSPAM_SLOTS];
static emit_log_hook_type pgfuzz_prev_emit_log_hook = NULL;
static int pgfuzz_logspam_enabled = -1;   /* -1 = not yet resolved */

static inline unsigned int
pgfuzz_logspam_hash(const char *s)
{
	/* FNV-1a. Cheap, and this runs inside error handling. */
	unsigned int h = 2166136261u;

	while (s != NULL && *s != '\0')
	{
		h ^= (unsigned char) *s++;
		h *= 16777619u;
	}
	return h;
}

/*
 * The hook itself.
 *
 * Runs inside elog's error path, so it allocates nothing, calls no elog, and
 * touches only its own static table and stderr. Recursion here would turn a log
 * line into a crash.
 */
static inline void
pgfuzz_logspam_hook(ErrorData *edata)
{
	const char *id;
	unsigned int h;
	int i, slot;

	if (pgfuzz_prev_emit_log_hook != NULL)
		(*pgfuzz_prev_emit_log_hook) (edata);

	if (pgfuzz_logspam_enabled < 0)
	{
		const char *v = getenv("PGFUZZ_LOG_ALL");

		pgfuzz_logspam_enabled = (v != NULL && v[0] == '1') ? 0 : 1;
	}
	if (!pgfuzz_logspam_enabled)
		return;

	/* Never throttle a PANIC, and never touch what is already silenced. */
	if (!edata->output_to_server || edata->elevel >= PANIC)
		return;

	/*
	 * message_id is the untranslated format string, so every instance of one
	 * ereport() site hashes the same however its parameters vary. Fall back to
	 * the translated text only if it is missing.
	 */
	id = edata->message_id ? edata->message_id : edata->message;
	if (id == NULL)
		return;

	h = pgfuzz_logspam_hash(id);
	slot = -1;
	for (i = 0; i < PGFUZZ_LOGSPAM_SLOTS; i++)
	{
		if (pgfuzz_logspam_tab[i].seen == 0)
		{
			if (slot < 0)
				slot = i;			/* first free, remember and keep looking */
			continue;
		}
		if (pgfuzz_logspam_tab[i].hash == h)
		{
			slot = i;
			break;
		}
	}

	/*
	 * Table full of distinct messages: pass everything through. A fuzz run that
	 * produces 128 different messages is not the flooding case this exists for,
	 * and silently dropping the 129th would be the failure mode this file is
	 * meant to prevent.
	 */
	if (slot < 0)
		return;

	if (pgfuzz_logspam_tab[slot].seen == 0)
	{
		pgfuzz_logspam_tab[slot].hash = h;
		pgfuzz_logspam_tab[slot].suppressed = 0;
		strncpy(pgfuzz_logspam_tab[slot].sample, id,
				sizeof(pgfuzz_logspam_tab[slot].sample) - 1);
		pgfuzz_logspam_tab[slot].sample[sizeof(pgfuzz_logspam_tab[slot].sample) - 1] = '\0';
	}
	pgfuzz_logspam_tab[slot].seen++;

	if (pgfuzz_logspam_tab[slot].seen <= PGFUZZ_LOGSPAM_LOUD)
		return;							/* early ones go through verbatim */

	if (pgfuzz_logspam_tab[slot].seen % PGFUZZ_LOGSPAM_EVERY == 0)
	{
		/*
		 * Let this one through AND say how many were dropped since the last
		 * time. The count is the point: silence that cannot be quantified is
		 * indistinguishable from the message having stopped.
		 */
		fprintf(stderr,
				"PGFUZZ LOG: \"%s\" seen %lu time(s), %lu suppressed since last report\n",
				pgfuzz_logspam_tab[slot].sample,
				pgfuzz_logspam_tab[slot].seen,
				pgfuzz_logspam_tab[slot].suppressed);
		pgfuzz_logspam_tab[slot].suppressed = 0;
		return;
	}

	pgfuzz_logspam_tab[slot].suppressed++;
	edata->output_to_server = false;
}

static inline void
pgfuzz_logspam_install(void)
{
	memset(pgfuzz_logspam_tab, 0, sizeof(pgfuzz_logspam_tab));
	pgfuzz_prev_emit_log_hook = emit_log_hook;
	emit_log_hook = pgfuzz_logspam_hook;
}

#endif							/* FUZZ_LOGSPAM_H */

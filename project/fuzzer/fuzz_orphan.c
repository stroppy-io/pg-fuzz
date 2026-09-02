/*-------------------------------------------------------------------------
 *
 * fuzz_orphan.c
 *	  Name the leaked memory context, instead of letting ASan guess.
 *
 * THE PROBLEM THIS SOLVES
 * ======================
 * ASan's allocation stack does not identify the context that leaked, for any
 * ALLOCSET_DEFAULT_SIZES or ALLOCSET_SMALL_SIZES context.  AllocSetDelete()
 * does not free such a context -- it parks it on a freelist of up to 100 per
 * size class (aset.c:627-663) -- and AllocSetContextCreateInternal() pops one
 * back WITHOUT calling malloc (aset.c:404-429).  ASan records a chunk's
 * allocation stack at malloc time and keeps it until free, so a recycled 8 KB
 * context header carries the stack of whichever site FIRST allocated that
 * chunk.  After roughly a hundred iterations the freelist is warm and nearly
 * every context creation inherits a stale stack.
 *
 * The cost of not knowing this: on 2026-08-16 a campaign reported fifteen
 * distinct "leak sites" -- spi_dest_startup, CreateExprContextInternal,
 * make_expanded_record_from_tupdesc and so on -- and a plan was built to
 * suppress them one by one.  They are one or two real leaks wearing many
 * masks.  Suppressing by allocation site would have suppressed a lie.
 *
 * This project had already seen the effect without recognising it, eleven days
 * earlier, in fuzz_canary.h:15-20: "The corpus run blamed compute_index_stats;
 * replaying the one input in isolation showed the real site, ExecVacuum."  A
 * fresh process has a cold freelist and therefore a true stack.
 *
 * WHY WATCHING CREATION IS ENOUGH
 * ==============================
 * An LSan *Direct* leak with no *Indirect* entries is a context with no
 * parent: MemoryContextDelete() deletes bottom-up (mcxt.c:474-493), so a
 * context whose parent is alive cannot be orphaned, and one whose parent also
 * leaked would be reported Indirect.
 *
 * A parentless context can only come from a site that parents to
 * PortalContext, which is NULL outside a portal (mcxt.c:158).  There are six
 * in the entire tree: vacuum.c:415, cluster.c:216, and three in indexcmds.c --
 * plus spi.c:161 in the non-atomic case, which this harness never reaches.
 *
 * So we do not need lifetime tracking, a registry, or a walk.  We need to
 * notice the creation of a ROOT context, which the harness never does
 * legitimately mid-iteration, and print its name.  context->name is a literal
 * from the caller ("Vacuum", "Reindex", "Cluster"), which is exactly the
 * answer ASan cannot give.
 *
 * --wrap works here because every one of those callers lives outside aset.c.
 * (The two references inside aset.c itself are not intercepted, which is fine:
 * neither creates a root.)  That subtlety cost a rebuild elsewhere today --
 * wrapping pq_getbytes did nothing because pq_getmessage calls it from inside
 * pqcomm.c, the same translation unit.
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include <stdio.h>
#include <stdlib.h>

#include "utils/memutils.h"

extern MemoryContext __real_AllocSetContextCreateInternal(MemoryContext parent,
														  const char *name,
														  Size minContextSize,
														  Size initBlockSize,
														  Size maxBlockSize);

/*
 * Root contexts created since the last reset.  Reported by name; the count
 * matters too, because a leak that happens once per input and one that happens
 * once per process need different fixes.
 */
static long pgfuzz_orphan_count = 0;
static bool pgfuzz_orphan_watch = false;

void		pgfuzz_orphan_begin(void);
long		pgfuzz_orphan_end(void);

/* Start watching.  Call at the top of an iteration, after startup is done. */
void
pgfuzz_orphan_begin(void)
{
	pgfuzz_orphan_watch = true;
	pgfuzz_orphan_count = 0;
}

/* Stop watching; returns how many root contexts were created. */
long
pgfuzz_orphan_end(void)
{
	pgfuzz_orphan_watch = false;
	return pgfuzz_orphan_count;
}

MemoryContext
__wrap_AllocSetContextCreateInternal(MemoryContext parent,
									 const char *name,
									 Size minContextSize,
									 Size initBlockSize,
									 Size maxBlockSize)
{
	/*
	 * Report BEFORE creating, so the message survives even if the creation
	 * itself dies -- and so the order in the log matches the order of events.
	 *
	 * Startup legitimately creates roots (TopMemoryContext itself, and the
	 * contexts MemoryContextInit builds), which is why this is gated on the
	 * watch flag rather than reporting unconditionally.
	 */
	if (pgfuzz_orphan_watch && parent == NULL)
	{
		pgfuzz_orphan_count++;
		fprintf(stderr,
				"PGFUZZ ORPHAN-CONTEXT: \"%s\" created with no parent "
				"(PortalContext was NULL)\n",
				name ? name : "(unnamed)");
	}

	return __real_AllocSetContextCreateInternal(parent, name, minContextSize,
											   initBlockSize, maxBlockSize);
}

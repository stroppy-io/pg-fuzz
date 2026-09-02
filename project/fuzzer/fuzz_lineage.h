/*-------------------------------------------------------------------------
 *
 * fuzz_lineage.h
 *	  Where every corpus input came from: its parent, and the mutation that
 *	  produced it.
 *
 * WHY
 * ===
 * A corpus is a pile of files named by content hash. Nothing records how any
 * of them came to be, so questions that ought to be answerable are not:
 *
 *	  - which seed is this input descended from?
 *	  - what chain of mutations produced the input that found this crash?
 *	  - when the capper drops an input, what lineage goes with it?
 *
 * The capper is the sharp case. It ranks inputs by BYTE SIZE, because size is
 * a cheap proxy for replay cost -- and corpus-minimize.sh's own header records
 * that the proxy fails: spi_query_fuzzer went 17,798 -> 4,430 inputs while
 * throughput fell 150 -> 50 execs/s. Ranking on anything better needs to know
 * what an input IS, and that starts with knowing where it came from.
 *
 * HOW
 * ===
 * libFuzzer calls LLVMFuzzerCustomMutator instead of its own mutator when the
 * symbol exists. This one is a PASS-THROUGH: it hashes the parent, calls
 * LLVMFuzzerMutate -- libFuzzer's own dispatcher, unchanged -- hashes the
 * result, and records the pair. Mutation behaviour is not altered; this
 * observes it.
 *
 * The hash is SHA1 because that is what libFuzzer names corpus files with, so
 * a child hash IS the filename the input will have if it is kept. Verified:
 *	  corpus/jsonb_fuzzer/a82c462fdb9f5d55e7031cac5193f907afff0b73
 *	  sha1sum of that file  == a82c462fdb9f5d55e7031cac5193f907afff0b73
 * Any other hash would produce records that cannot be joined to the corpus.
 *
 * Most children are discarded -- libFuzzer keeps only inputs that add
 * coverage -- so the log records far more edges than the corpus has files.
 * That is deliberate: an edge whose child never appears on disk is a mutation
 * that led nowhere, and knowing which mutations lead nowhere is half the
 * question. Disk is not a constraint here.
 *
 * OPT-IN AT RUNTIME. Nothing happens unless PGFUZZ_LINEAGE is set to a
 * writable path. A target built with this header and run without the variable
 * behaves exactly as before, so the feature cannot break a campaign by being
 * compiled in.
 *
 *-------------------------------------------------------------------------
 */
#ifndef FUZZ_LINEAGE_H
#define FUZZ_LINEAGE_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

size_t LLVMFuzzerMutate(uint8_t *Data, size_t Size, size_t MaxSize);

/* ---------------------------------------------------------------- SHA-1 */
typedef struct { uint32_t h[5]; uint64_t len; uint8_t buf[64]; size_t n; } fl_sha1;

static void
fl_sha1_block(fl_sha1 *c, const uint8_t *p)
{
	uint32_t	w[80], a, b, d, e, f, k, t;
	int			i;

	for (i = 0; i < 16; i++)
		w[i] = (uint32_t) p[i * 4] << 24 | (uint32_t) p[i * 4 + 1] << 16
			| (uint32_t) p[i * 4 + 2] << 8 | (uint32_t) p[i * 4 + 3];
	for (i = 16; i < 80; i++)
	{
		t = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16];
		w[i] = (t << 1) | (t >> 31);
	}
	a = c->h[0]; b = c->h[1]; d = c->h[2]; e = c->h[3];
	{
		uint32_t	g = c->h[4];

		for (i = 0; i < 80; i++)
		{
			if (i < 20)      { f = (b & d) | (~b & e);            k = 0x5a827999; }
			else if (i < 40) { f = b ^ d ^ e;                     k = 0x6ed9eba1; }
			else if (i < 60) { f = (b & d) | (b & e) | (d & e);   k = 0x8f1bbcdc; }
			else             { f = b ^ d ^ e;                     k = 0xca62c1d6; }
			t = ((a << 5) | (a >> 27)) + f + g + k + w[i];
			g = e; e = d; d = (b << 30) | (b >> 2); b = a; a = t;
		}
		c->h[0] += a; c->h[1] += b; c->h[2] += d; c->h[3] += e; c->h[4] += g;
	}
}

static void
fl_sha1_hex(const uint8_t *data, size_t len, char out[41])
{
	fl_sha1		c;
	uint8_t		pad[72];
	size_t		i,
				r;
	uint64_t	bits = (uint64_t) len * 8;

	c.h[0] = 0x67452301; c.h[1] = 0xefcdab89; c.h[2] = 0x98badcfe;
	c.h[3] = 0x10325476; c.h[4] = 0xc3d2e1f0;

	for (i = 0; i + 64 <= len; i += 64)
		fl_sha1_block(&c, data + i);
	r = len - i;
	memcpy(pad, data + i, r);
	pad[r++] = 0x80;
	/* one block if the length fits, two if it does not */
	if (r > 56)
	{
		memset(pad + r, 0, 64 - r);
		fl_sha1_block(&c, pad);
		r = 0;
		memset(pad, 0, 56);
	}
	else
		memset(pad + r, 0, 56 - r);
	for (i = 0; i < 8; i++)
		pad[56 + i] = (uint8_t) (bits >> (56 - 8 * i));
	fl_sha1_block(&c, pad);

	for (i = 0; i < 5; i++)
		snprintf(out + i * 8, 9, "%08x", c.h[i]);
	out[40] = '\0';
}

/* ------------------------------------------------------------- recorder */
static FILE *fl_out = NULL;
static int	fl_ready = 0;
static unsigned long long fl_seq = 0;

static void
fl_init(void)
{
	const char *p = getenv("PGFUZZ_LINEAGE");

	fl_ready = 1;
	if (p == NULL || *p == '\0')
		return;					/* opt-in: unset means do nothing at all */
	fl_out = fopen(p, "ae");	/* O_APPEND: workers share one file safely */
	if (fl_out != NULL)
		setvbuf(fl_out, NULL, _IOFBF, 1 << 20);
}

/*
 * The pass-through mutator.
 *
 * Records child <- parent for every mutation attempted, kept or not. Writes
 * are buffered at 1MB and appended, so the cost per mutation is two SHA-1s
 * over a <= max_len buffer -- at the 7,500 exec/s these targets reach, that is
 * far below the cost of the input itself.
 */
size_t
LLVMFuzzerCustomMutator(uint8_t *Data, size_t Size, size_t MaxSize,
						unsigned int Seed)
{
	char		parent[41];
	char		child[41];
	size_t		n;

	if (!fl_ready)
		fl_init();

	if (fl_out == NULL)
		return LLVMFuzzerMutate(Data, Size, MaxSize);

	fl_sha1_hex(Data, Size, parent);
	n = LLVMFuzzerMutate(Data, Size, MaxSize);
	fl_sha1_hex(Data, n, child);

	/*
	 * seq, child, parent, sizes, seed.
	 *
	 * The child hash is the corpus FILENAME libFuzzer will use if it keeps this
	 * input, which is what makes the record joinable to the corpus on disk.
	 *
	 * SEQ is the mutation ordinal within this process. It exists because
	 * libFuzzer reports the mutation OPERATORS ("MS: 5 InsertByte-EraseBytes-")
	 * only in its log, on the lines for inputs it KEEPS, and those lines carry
	 * no hash. The ordinal is what lets a kept input be joined back to the log
	 * line that describes how it was made -- without it the two records share
	 * no key at all and the operator names are unrecoverable.
	 *
	 * Recording every attempt, not only the keepers: a mutation that led
	 * nowhere is half of what a capper would need to rank an input, and the
	 * disk this costs was explicitly not a constraint.
	 */
	fprintf(fl_out, "%llu %s %s %zu %zu %u\n",
			(unsigned long long) ++fl_seq, child, parent, n, Size, Seed);
	return n;
}

#endif							/* FUZZ_LINEAGE_H */

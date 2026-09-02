/*-------------------------------------------------------------------------
 *
 * numeric_fuzzer.c
 *	  Fuzz numeric parsing, output and arithmetic.
 *
 * numeric.c implements arbitrary-precision decimal arithmetic by hand, on a
 * packed variable-length representation with its own weight/scale/sign
 * encoding.  That combination -- hand-rolled bignum plus a wire format that a
 * client controls -- is exactly where overflow and off-by-one bugs live, and
 * it is a much better UBSan target than it is an ASan target.
 *
 * Input format: an optional second operand may be supplied after the first
 * newline, so that binary operators get two fuzzer-controlled values rather
 * than one fuzzed value and one constant.
 *
 *-------------------------------------------------------------------------
 */
#include "fuzz_util.h"
#include "fuzz_lineage.h"

#include "utils/fmgrprotos.h"
#include "utils/numeric.h"

/*
 * Arithmetic on two multi-thousand-digit numerics is quadratic and will spend
 * the whole fuzzing budget in one input.  Parsing stays unbounded -- that is
 * the part we most want covered -- but the operator pass is skipped for very
 * long operands.
 */
#define MAX_OPERAND_LEN 512

static const PGFunction binary_ops[] = {
	numeric_add,
	numeric_sub,
	numeric_mul,
	numeric_div,
	numeric_mod,
	numeric_power,
	numeric_gcd,
	numeric_lcm,
	numeric_log,				/* log(base, value) */
};

static const PGFunction unary_ops[] = {
	numeric_uminus,
	numeric_abs,
	numeric_sqrt,
	numeric_ln,
	numeric_exp,
	numeric_sign,
	numeric_inc,
};

static void
body(const char *s, size_t len, int sel)
{
	const char *nl;
	char	   *first;
	Datum		a;
	Datum		b;
	size_t		firstlen;

	/* split "<value>\n<value>" into two operands */
	nl = strchr(s, '\n');
	firstlen = nl ? (size_t) (nl - s) : strlen(s);

	first = palloc(firstlen + 1);
	memcpy(first, s, firstlen);
	first[firstlen] = '\0';

	a = DirectFunctionCall3(numeric_in, CStringGetDatum(first),
							ObjectIdGetDatum(InvalidOid), Int32GetDatum(-1));

	/* round-trip through the output function */
	(void) DirectFunctionCall1(numeric_out, a);

	if (firstlen > MAX_OPERAND_LEN)
		return;

	if (nl != NULL)
	{
		if (strlen(nl + 1) > MAX_OPERAND_LEN)
			return;
		b = DirectFunctionCall3(numeric_in, CStringGetDatum(nl + 1),
								ObjectIdGetDatum(InvalidOid), Int32GetDatum(-1));
	}
	else
	{
		b = DirectFunctionCall3(numeric_in, CStringGetDatum("1"),
								ObjectIdGetDatum(InvalidOid), Int32GetDatum(-1));
	}

	(void) DirectFunctionCall2(binary_ops[sel % lengthof(binary_ops)], a, b);
	(void) DirectFunctionCall1(unary_ops[sel % lengthof(unary_ops)], a);

	/* scale-changing paths have their own rounding code */
	(void) DirectFunctionCall2(numeric_round, a, Int32GetDatum((int32) (sel % 40) - 20));
	(void) DirectFunctionCall2(numeric_trunc, a, Int32GetDatum((int32) (sel % 40) - 20));
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
	int			sel = pgfuzz_select(&data, &size, 64);

	pgfuzz_run(body, data, size, sel);
	return 0;
}

/*
 * Copyright 2021 Google LLC
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 */

#include "gf128.h"
#include "polyval.h"

/*
 * This file provides generic and simd implementations of POLYVAL.
 * The generic and simd implementations produce matching outputs, but
 * they operate in fundamentally different ways.
 *
 * POLYVAL is designed to operate in three isomorphic finite fields.
 * These fields are:
 *
 *	1) Elements of GF(128) where multiplication is normal polynomial
 *	multiplication modulo the irreducible polynomial: x^128 + x^127 + x^126 +
 *	x^121 + 1
 *
 *	2) Elements of GF(128) in montgomery where multiplication a*b is defined as
 *	montgomery multiplication. Montgomery multiplication is defined by taking
 *	the normal polynomial product, multiplying by x^{-128}, then reducing by the
 *	irreducible polynomial: x^128 + x^127 + x^126 + x^121 + 1
 *
 *	3) Elements of GF(128) where multiplication is normal polynomial
 *	multiplication modulo the irreducible polynomial: x^128 + x^7 + x^2 + x + 1
 *
 * 
 * The implementation differences arise because the simd implementation is more
 * efficient when using field (3). Likewise, the generic implementation can
 * reuse pre-existing finite field code by operating in field (2). The final
 * outputs are then mapped into field (1). By transforming the elements of one
 * field to another via field isomorphisms, we can perform computations in
 * whichever field is convenient.
 *
 * The field isomorphisms are described as follows:
 * 	Field (1) -> Field(2)
 * 		a -> x^128*a
 * 	Field (2) -> Field(3)
 * 		a -> x*reverse_bytes(a)
 *
 * When computing POLYVAL, the key h is assumed to be in field (2). The
 * message elements are assumed to be in field (1). The output is also
 * assumed to be in field (1).
 *
 *
 * When computing simd-POLYVAL, we require an implementation of montgomery
 * multiplication as specified in the definition of field (2). Powers of h
 * are computed normally in field (2). Then montgomery multiplication is
 * performed on these powers of h in field (2) and the message elements
 * in field (1). This works for the following reasons:
 *
 * 1) Mapping a field element from field (1) to field (2) requires
 * multiplying by x^{128}.
 * 2) Montgomery multiplication requires multiplying by
 * x^{-128}. 
 * 3) Mapping a field element from field (2) to field (1) requires
 * multiplying by x^{-128}. 
 *
 * Steps 1 and 3 can be omitted since they cancel each
 * other. Thus we are left with the final product in field (1).
 *
 *
 * When computing generic-POLYVAL, we require an implementation of normal
 * finite field multiplication in field (3). We first map h from field (2) to
 * field (3) using the isomorphism above. We compute powers of h in field (3).
 * Then the powers of h in field (3) are multiplied by reverse_bytes(M) where M
 * is a message element in field (1). This works for the following reasons:
 * 
 * 1) Mapping a field element from field (1) to field (3) is done by computing
 * b = x*reverse_bytes(x^128*a). 
 * 2) Mapping an element from field (3) to field (1) is done by computing
 * x^{-128}*reverse_bytes(x^{-1}*(b*h^k)).
 *
 * The multiplication by x can be omitted since it will be cancelled when
 * multiplying by x^{-1}. Furthermore, the x^{128} and x^{-128} will also cancel
 * eachother, so they can both be omitted. Thus we are left with the final
 * product in field (1).
 */

#ifdef __x86_64__
asmlinkage void clmul_polyval_update(const u8 *in,
				     const struct polyval_key *keys,
				     uint64_t nblocks, ble128 *accumulator);
asmlinkage void clmul_polyval_mul(ble128 *op1, const ble128 *op2);
#define POLYVAL clmul_polyval_update
#define MUL clmul_polyval_mul
#endif
#ifdef __aarch64__
asmlinkage void pmull_polyval_update(const u8 *in,
				     const struct polyval_key *keys,
				     uint64_t nblocks, ble128 *accumulator);
asmlinkage void pmull_polyval_mul(ble128 *op1, const ble128 *op2);
#define POLYVAL pmull_polyval_update
#define MUL pmull_polyval_mul
#endif
#if !defined(__x86_64__) && !defined(__aarch64__)
#error Unsupported architecture.
#endif

/*
 * Used to convert "GHASH-like" multiplication into "POLYVAL-like".
 * See https://datatracker.ietf.org/doc/html/rfc8452 for more detail.
 */
void reverse_bytes(be128 *a)
{
	swap(a->a, a->b);
	a->a = __builtin_bswap64(a->a);
	a->b = __builtin_bswap64(a->b);
}

static void polyval_setkey_generic(struct polyval_key *key, const u8 *raw_key)
{
	be128 *h = &key->key.generic_h;

	memcpy(h, raw_key, sizeof(be128));

	reverse_bytes(h);
	gf128mul_x_lle(h, h);
}

static void polyval_setkey_simd(struct polyval_key *key, const u8 *raw_key)
{
	ble128 *powers = key->key.simd_powers;

	/* set h */
	memcpy(&powers[NUM_PRECOMPUTE_KEYS - 1], raw_key, sizeof(ble128));

	/* Precompute key powers */
	for (int i = NUM_PRECOMPUTE_KEYS - 2; i >= 0; i--) {
		memcpy(&powers[i], &powers[NUM_PRECOMPUTE_KEYS - 1],
		       sizeof(ble128));
		MUL(&(powers[i]), &(powers[(i + 1)]));
	}
}

void polyval_setkey(struct polyval_key *key, const u8 *raw_key, bool simd)
{
	if (simd) {
		polyval_setkey_simd(key, raw_key);
	} else {
		polyval_setkey_generic(key, raw_key);
	}
}

void polyval_generic(const u8 *in, const struct polyval_key *key,
		     uint64_t nblocks, be128 *accumulator)
{
	const be128 *h = &key->key.generic_h;
	be128 tmp;

	while (nblocks > 0) {
		memcpy(&tmp, in, sizeof(be128));
		reverse_bytes(&tmp);
		be128_xor(accumulator, accumulator, &tmp);
		gf128mul_lle(accumulator, h);
		in += 16;
		nblocks--;
	}
}

/*
 * If the message is not a multiple of 16 bytes, the last block should be
 * padded and passed as final_block. This allows callers of polyval to use
 * their own padding method without paying any additional performance cost.
 */
void polyval_update(struct polyval_state *state, const struct polyval_key *key,
		    const u8 *in, size_t nblocks, bool simd)
{
	if (simd)
		POLYVAL(in, key, nblocks, &state->state.simd_state);
	else
		polyval_generic(in, key, nblocks, &state->state.generic_state);
}

void polyval_emit(struct polyval_state *state, u8 out[POLYVAL_DIGEST_SIZE],
		  bool simd)
{
	if (!simd) {
		reverse_bytes(&state->state.generic_state);
		memcpy(out, &state->state.generic_state, POLYVAL_DIGEST_SIZE);
	} else {
		memcpy(out, &state->state.simd_state, POLYVAL_DIGEST_SIZE);
	}
}

static void _polyval(const struct polyval_key *key, const void *src,
		     unsigned int srclen, u8 *digest, bool simd)
{
	struct polyval_state polystate;
	size_t nblocks = srclen / POLYVAL_BLOCK_SIZE;

	ASSERT(srclen % POLYVAL_BLOCK_SIZE == 0);

	polyval_init(&polystate);
	polyval_update(&polystate, key, src, nblocks, simd);
	polyval_emit(&polystate, digest, simd);
}

static void _polyval_generic(const struct polyval_key *key, const void *src,
			     unsigned int srclen, u8 *digest)
{
	_polyval(key, src, srclen, digest, false);
}

static void _polyval_simd(const struct polyval_key *key, const void *src,
			  unsigned int srclen, u8 *digest)
{
	_polyval(key, src, srclen, digest, true);
}

void test_polyval(void)
{
#define ALGNAME "Polyval"
#define HASH _polyval_generic
#define HASH_SIMD _polyval_simd
#define SIMD_IMPL_NAME "clmul"
#define KEY struct polyval_key
#define SETKEY polyval_setkey_generic
#define SETKEY_SIMD polyval_setkey_simd
#define KEY_BYTES POLYVAL_KEY_SIZE
#define DIGEST_SIZE POLYVAL_DIGEST_SIZE
#include "hash_benchmark_template.h"
}

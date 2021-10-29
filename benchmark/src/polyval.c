/*
 * Copyright 2021 Google LLC
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 */

#include "gf128.h"
#include "polyval.h"

#ifdef __x86_64__
asmlinkage void clmul_polyval_update(const u8 *in,
				     const struct polyval_key *keys,
				     uint64_t nbytes, ble128 *accumulator);
asmlinkage void clmul_polyval_mul(ble128 *op1, const ble128 *op2);
#define POLYVAL clmul_polyval_update
#define MUL clmul_polyval_mul
#endif
#ifdef __aarch64__
asmlinkage void pmull_polyval_update(const u8 *in,
				     const struct polyval_key *keys,
				     uint64_t nbytes, ble128 *accumulator);
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
		     uint64_t nbytes, be128 *accumulator)
{
	const be128 *h = &key->key.generic_h;
	size_t nblocks = nbytes / POLYVAL_BLOCK_SIZE;
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
		    const u8 *in, size_t nbytes, bool simd)
{
	if (simd) {
		POLYVAL(in, key, nbytes, &state->state.simd_state);
	} else {
		polyval_generic(in, key, nbytes, &state->state.generic_state);
	}
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
	polyval_init(&polystate);
	polyval_update(&polystate, key, src, srclen, simd);
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

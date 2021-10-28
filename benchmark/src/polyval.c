/*
 * Copyright 2021 Google LLC
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 */

#include "gf128.h"
#include "polyval.h"

#ifdef __x86_64__
asmlinkage void clmul_polyval(const u8 *in, const struct polyval_key *keys,
			      uint64_t nbytes, const u128 *final,
			      u128 *accumulator);
asmlinkage void clmul_polyval_mul(u128 *op1, const u128 *op2);
#define POLYVAL clmul_polyval
#define MUL clmul_polyval_mul
#endif
#ifdef __aarch64__
asmlinkage void pmull_polyval(const u8 *in, const struct polyval_key *keys,
			      uint64_t nbytes, const u128 *final,
			      u128 *accumulator);
asmlinkage void pmull_polyval_mul(u128 *op1, const u128 *op2);
#define POLYVAL pmull_polyval
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
	/* set h */
	memcpy(&key->powers[NUM_PRECOMPUTE_KEYS - 1], raw_key, sizeof(u128));

	reverse_bytes((be128 *)&key->powers[NUM_PRECOMPUTE_KEYS - 1]);
	gf128mul_x_lle((be128 *)&key->powers[NUM_PRECOMPUTE_KEYS - 1],
		       (be128 *)&key->powers[NUM_PRECOMPUTE_KEYS - 1]);

	/* Precompute key powers */
	for (int i = NUM_PRECOMPUTE_KEYS - 2; i >= 0; i--) {
		memcpy(&key->powers[i], &key->powers[NUM_PRECOMPUTE_KEYS - 1],
		       sizeof(u128));
		gf128mul_lle((be128 *)&(key->powers[i]),
			     (be128 *)&(key->powers[(i + 1)]));
	}
}

static void polyval_setkey_simd(struct polyval_key *key, const u8 *raw_key)
{
	/* set h */
	memcpy(&key->powers[NUM_PRECOMPUTE_KEYS - 1], raw_key, sizeof(u128));

	/* Precompute key powers */
	for (int i = NUM_PRECOMPUTE_KEYS - 2; i >= 0; i--) {
		memcpy(&key->powers[i], &key->powers[NUM_PRECOMPUTE_KEYS - 1],
		       sizeof(u128));
		MUL(&(key->powers[i]), &(key->powers[(i + 1)]));
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

void polyval_init(struct polyval_state *state)
{
	memset(state, 0, sizeof(struct polyval_state));
}

void polyval_generic(const u8 *in, const struct polyval_key *key,
		     uint64_t nbytes, const u8 *final, be128 *accumulator)
{
	be128 tmp;
	int index = 0;
	int final_shift;
	size_t nblocks;
	nblocks = nbytes / POLYVAL_BLOCK_SIZE;
	while (nblocks >= NUM_PRECOMPUTE_KEYS) {
		gf128mul_lle(accumulator, (be128 *)&key->powers[0]);
		for (int i = 0; i < NUM_PRECOMPUTE_KEYS; i++) {
			memcpy(&tmp, &in[(i + index) * POLYVAL_BLOCK_SIZE],
			       sizeof(u128));
			reverse_bytes(&tmp);
			gf128mul_lle(&tmp, (be128 *)&key->powers[i]);
			be128_xor(accumulator, accumulator, (be128 *)&tmp);
		}
		index += NUM_PRECOMPUTE_KEYS;
		nblocks -= NUM_PRECOMPUTE_KEYS;
	}
	final_shift = nbytes % POLYVAL_BLOCK_SIZE == 0 ? 0 : 1;
	if (nblocks > 0 || final_shift == 1) {
		/* 0 <= NUM_PRECOMPUTE_KEYS - nblocks - final_shift <
		 * NUM_PRECOMPUTE_KEYS */
		gf128mul_lle(accumulator,
			     (be128 *)&key->powers[NUM_PRECOMPUTE_KEYS - nblocks
						   - final_shift]);
		for (int i = 0; i < nblocks; i++) {
			memcpy(&tmp, &in[(i + index) * POLYVAL_BLOCK_SIZE],
			       sizeof(u128));
			reverse_bytes(&tmp);
			gf128mul_lle((be128 *)&tmp,
				     (be128 *)&key->powers[NUM_PRECOMPUTE_KEYS
							   - nblocks
							   - final_shift + i]);
			be128_xor(accumulator, accumulator, (be128 *)&tmp);
		}
		index += nblocks;
		nblocks -= nblocks;
		if (final_shift == 1) {
			memcpy(&tmp, final, sizeof(u128));
			reverse_bytes(&tmp);
			gf128mul_lle(
				(be128 *)&tmp,
				(be128 *)&key->powers[NUM_PRECOMPUTE_KEYS - 1]);
			be128_xor(accumulator, accumulator, (be128 *)&tmp);
		}
	}
}

/*
 * If the message is not a multiple of 16 bytes, the last block should be
 * padded and passed as final_block. This allows callers of polyval to use
 * their own padding method without paying any additional performance cost.
 */
void polyval_update(struct polyval_state *state, const struct polyval_key *key,
		    const u8 *in, size_t nbytes,
		    const u8 final_block[POLYVAL_BLOCK_SIZE], bool simd)
{
	if (simd)
		POLYVAL(in, key, nbytes, final_block, &state->state);
	else
		polyval_generic(in, key, nbytes, final_block,
				(be128 *)&state->state);
}

void polyval_emit(struct polyval_state *state, u8 out[POLYVAL_DIGEST_SIZE],
		  bool simd)
{
	if (simd)
		memcpy(out, &state->state, POLYVAL_DIGEST_SIZE);
	else {
		reverse_bytes((be128 *)&state->state);
		memcpy(out, &state->state, POLYVAL_DIGEST_SIZE);
	}
}

static void _polyval_generic(const struct polyval_key *key, const void *src,
			     unsigned int srclen, u8 *digest)
{
	struct polyval_state polystate;
	polyval_init(&polystate);

	// Pad partial blocks since polyval can only handle 16-byte multiples.
	u128 padded_final;
	if (srclen % POLYVAL_BLOCK_SIZE != 0) {
		padded_final.a = 0;
		padded_final.b = 0;
		memcpy(&padded_final,
		       src + POLYVAL_BLOCK_SIZE * (srclen / POLYVAL_BLOCK_SIZE),
		       srclen % POLYVAL_BLOCK_SIZE);
	}
	polyval_update(&polystate, key, src, srclen, &padded_final, false);
	polyval_emit(&polystate, digest, false);
}

static void _polyval_simd(const struct polyval_key *key, const void *src,
			  unsigned int srclen, u8 *digest)
{
	struct polyval_state polystate;
	polyval_init(&polystate);

	// Pad partial blocks since polyval can only handle 16-byte multiples.
	u128 padded_final;
	if (srclen % POLYVAL_BLOCK_SIZE != 0) {
		padded_final.a = 0;
		padded_final.b = 0;
		memcpy(&padded_final,
		       src + POLYVAL_BLOCK_SIZE * (srclen / POLYVAL_BLOCK_SIZE),
		       srclen % POLYVAL_BLOCK_SIZE);
	}
	polyval_update(&polystate, key, src, srclen, &padded_final, true);
	polyval_emit(&polystate, digest, true);
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

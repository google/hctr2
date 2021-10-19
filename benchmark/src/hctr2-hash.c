/*
 * Copyright 2021 Google LLC
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 */

#include "gf128.h"
#include "hctr2-hash.h"

#ifdef __x86_64__
asmlinkage void clmul_hctr2_polyval(const u8 *in,
				    const struct hctr2_hash_key *keys,
				    uint64_t nbytes, const u128 *final,
				    u128 *accumulator);
asmlinkage void clmul_hctr2_mul(u128 *op1, const u128 *op2);
#define POLYVAL clmul_hctr2_polyval
#define MUL clmul_hctr2_mul
#endif
#ifdef __aarch64__
asmlinkage void pmull_hctr2_polyval(const u8 *in,
				    const struct hctr2_hash_key *keys,
				    uint64_t nbytes, const u128 *final,
				    u128 *accumulator);
asmlinkage void pmull_hctr2_mul(u128 *op1, const u128 *op2);
#define POLYVAL pmull_hctr2_polyval
#define MUL pmull_hctr2_mul
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

void hctr2_hash_setup_generic(struct hctr2_hash_key *key, const u8 *raw_key,
			      size_t tweak_len)
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
	key->tweaklen_part[0].b = tweak_len * 8 * 2 + 3;
	key->tweaklen_part[0].a = 0;
	reverse_bytes((be128 *)&key->tweaklen_part[0]);
	gf128mul_lle((be128 *)&key->tweaklen_part[0],
		     (be128 *)&key->powers[NUM_PRECOMPUTE_KEYS - 1]);
	key->tweaklen_part[1].b = tweak_len * 8 * 2 + 2;
	key->tweaklen_part[1].a = 0;
	reverse_bytes((be128 *)&key->tweaklen_part[1]);
	gf128mul_lle((be128 *)&key->tweaklen_part[1],
		     (be128 *)&key->powers[NUM_PRECOMPUTE_KEYS - 1]);
}

void hctr2_hash_setup_simd(struct hctr2_hash_key *key, const u8 *raw_key,
			   size_t tweak_len)
{
	/* set h */
	memcpy(&key->powers[NUM_PRECOMPUTE_KEYS - 1], raw_key, sizeof(u128));

	/* Precompute key powers */
	for (int i = NUM_PRECOMPUTE_KEYS - 2; i >= 0; i--) {
		memcpy(&key->powers[i], &key->powers[NUM_PRECOMPUTE_KEYS - 1],
		       sizeof(u128));
		MUL(&(key->powers[i]), &(key->powers[(i + 1)]));
	}
	key->tweaklen_part[0].b = tweak_len * 8 * 2 + 3;
	key->tweaklen_part[0].a = 0;
	MUL(&key->tweaklen_part[0], &key->powers[NUM_PRECOMPUTE_KEYS - 1]);
	key->tweaklen_part[1].b = tweak_len * 8 * 2 + 2;
	key->tweaklen_part[1].a = 0;
	MUL(&key->tweaklen_part[1], &key->powers[NUM_PRECOMPUTE_KEYS - 1]);
}

void hctr2_hash_setup(struct hctr2_hash_key *key, const u8 *raw_key,
		      size_t tweak_len, bool simd)
{
	if (simd) {
		hctr2_hash_setup_simd(key, raw_key, tweak_len);
	} else {
		hctr2_hash_setup_generic(key, raw_key, tweak_len);
	}
}

void generic_hctr2_poly(const u8 *in, const struct hctr2_hash_key *key,
			uint64_t nbytes, const u8 *final, be128 *accumulator)
{
	be128 tmp;
	int index = 0;
	int final_shift;
	size_t nblocks;
	nblocks = nbytes / HCTR2_HASH_BLOCK_SIZE;
	while (nblocks >= NUM_PRECOMPUTE_KEYS) {
		gf128mul_lle(accumulator, (be128 *)&key->powers[0]);
		for (int i = 0; i < NUM_PRECOMPUTE_KEYS; i++) {
			memcpy(&tmp, &in[(i + index) * HCTR2_HASH_BLOCK_SIZE],
			       sizeof(u128));
			reverse_bytes(&tmp);
			gf128mul_lle(&tmp, (be128 *)&key->powers[i]);
			be128_xor(accumulator, accumulator, (be128 *)&tmp);
		}
		index += NUM_PRECOMPUTE_KEYS;
		nblocks -= NUM_PRECOMPUTE_KEYS;
	}
	final_shift = nbytes % HCTR2_HASH_BLOCK_SIZE == 0 ? 0 : 1;
	if (nblocks > 0 || final_shift == 1) {
		/* 0 <= NUM_PRECOMPUTE_KEYS - nblocks - final_shift <
		 * NUM_PRECOMPUTE_KEYS */
		gf128mul_lle(accumulator,
			     (be128 *)&key->powers[NUM_PRECOMPUTE_KEYS - nblocks
						   - final_shift]);
		for (int i = 0; i < nblocks; i++) {
			memcpy(&tmp, &in[(i + index) * HCTR2_HASH_BLOCK_SIZE],
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

void hctr2_hash_hash_tweak(const struct hctr2_hash_key *key,
			   struct hctr2_hash_state *state, const u8 *data,
			   size_t nbytes, bool mdiv, bool simd)
{
	u128 padded_final;
	memcpy(&state->state, &key->tweaklen_part[mdiv ? 1 : 0],
	       sizeof(state->state));
	if (nbytes % HCTR2_HASH_BLOCK_SIZE != 0) {
		padded_final.a = 0;
		padded_final.b = 0;
		memcpy(&padded_final,
		       data
			       + HCTR2_HASH_BLOCK_SIZE
					 * (nbytes / HCTR2_HASH_BLOCK_SIZE),
		       nbytes % HCTR2_HASH_BLOCK_SIZE);
	}
	if (simd) {
		POLYVAL(data, key, nbytes, &padded_final, &state->state);
	} else {
		generic_hctr2_poly(data, key, nbytes, (u8 *)&padded_final,
				   (be128 *)&state->state);
	}
}

void hctr2_hash_hash_message(const struct hctr2_hash_key *key,
			     struct hctr2_hash_state *state, const u8 *data,
			     size_t nbytes, bool simd)
{
	u128 padded_final;
	if (nbytes % HCTR2_HASH_BLOCK_SIZE != 0) {
		padded_final.a = 0;
		padded_final.b = 0;
		memcpy(&padded_final,
		       data
			       + HCTR2_HASH_BLOCK_SIZE
					 * (nbytes / HCTR2_HASH_BLOCK_SIZE),
		       nbytes % HCTR2_HASH_BLOCK_SIZE);
		((u8 *)(&padded_final))[nbytes % HCTR2_HASH_BLOCK_SIZE] = 0x01;
	}
	if (simd) {
		POLYVAL(data, key, nbytes, &padded_final, &state->state);
	} else {
		generic_hctr2_poly(data, key, nbytes, (u8 *)&padded_final,
				   (be128 *)&state->state);
	}
}

void hctr2_hash_emit(const struct hctr2_hash_key *key,
		     struct hctr2_hash_state *state, u8 *out, bool simd)
{
	memcpy(out, &state->state, HCTR2_HASH_BLOCK_SIZE);
	if (!simd) {
		reverse_bytes((be128 *)out);
	}
}

static void _polyval_generic(const struct hctr2_hash_key *key, const void *src,
			     unsigned int srclen, u8 *digest)
{
	struct hctr2_hash_state polystate;
	polystate.state.a = 0;
	polystate.state.b = 0;

	hctr2_hash_hash_message(key, &polystate, src, srclen, false);
	hctr2_hash_emit(key, &polystate, digest, false);
}

static void _polyval_simd(const struct hctr2_hash_key *key, const void *src,
			  unsigned int srclen, u8 *digest)
{
	struct hctr2_hash_state polystate;
	polystate.state.a = 0;
	polystate.state.b = 0;

	hctr2_hash_hash_message(key, &polystate, src, srclen, true);
	hctr2_hash_emit(key, &polystate, digest, true);
}

void polyval_setkey_generic(struct hctr2_hash_key *key, const u8 *raw_key)
{
	hctr2_hash_setup_generic(key, raw_key, 0);
}

void polyval_setkey_simd(struct hctr2_hash_key *key, const u8 *raw_key)
{
	hctr2_hash_setup_simd(key, raw_key, 0);
}

void test_polyval(void)
{
#define ALGNAME "Polyval"
#define HASH _polyval_generic
#define HASH_SIMD _polyval_simd
#define SIMD_IMPL_NAME "clmul"
#define KEY struct hctr2_hash_key
#define SETKEY polyval_setkey_generic
#define SETKEY_SIMD polyval_setkey_simd
#define KEY_BYTES HCTR2_HASH_KEY_SIZE
#define DIGEST_SIZE HCTR2_HASH_DIGEST_SIZE
#include "hash_benchmark_template.h"
}

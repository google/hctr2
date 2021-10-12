/*
 * HCTR polyhash
 *
 * Copyright 2021 Google LLC
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 *	 
 * Author: Nathan Huckleberry <nhuck@google.com>
 */

#include "gf128.h"
#include "hctr-polyhash.h"

#ifdef __x86_64__
asmlinkage void clmul_hctr2_poly(const u8 *in, const struct polyhash_key* keys, uint64_t nbytes, const u128* final, u128* accumulator);
asmlinkage void clmul_hctr2_mul(u128* op1, const u128* op2);
#define POLY clmul_hctr2_poly
#define MUL clmul_hctr2_mul
#endif
#ifdef __aarch64__
asmlinkage void pmull_hctr2_poly(const u8 *in, const struct polyhash_key* keys, uint64_t nbytes, const u128* final, u128* accumulator);
asmlinkage void pmull_hctr2_mul(u128* op1, const u128* op2);
#define POLY pmull_hctr2_poly
#define MUL pmull_hctr2_mul
#endif

void reverse(be128* a){
    swap(a->a, a->b);
    a->a = __builtin_bswap64(a->a);
    a->b = __builtin_bswap64(a->b);
}

void polyhash_setkey_generic(struct polyhash_key *key, const u8 *raw_key)
{
    /* set h */
	memcpy(&key->powers[NUM_PRECOMPUTE_KEYS-1], raw_key, sizeof(u128));

    reverse((be128*)&key->powers[NUM_PRECOMPUTE_KEYS-1]);
    gf128mul_x_lle((be128*)&key->powers[NUM_PRECOMPUTE_KEYS-1], (be128*)&key->powers[NUM_PRECOMPUTE_KEYS-1]);

	/* Precompute key powers */   
	for(int i = NUM_PRECOMPUTE_KEYS-2; i >= 0; i--) {
		memcpy(&key->powers[i], &key->powers[NUM_PRECOMPUTE_KEYS-1], sizeof(u128));
		gf128mul_lle((be128*)&(key->powers[i]), (be128*)&(key->powers[(i + 1)]));
	}
}

void polyhash_setkey_simd(struct polyhash_key *key, const u8 *raw_key)
{
    /* set h */
	memcpy(&key->powers[NUM_PRECOMPUTE_KEYS-1], raw_key, sizeof(u128));

	/* Precompute key powers */
	for(int i = NUM_PRECOMPUTE_KEYS-2; i >= 0; i--) {
		memcpy(&key->powers[i], &key->powers[NUM_PRECOMPUTE_KEYS-1], sizeof(u128));
		MUL(&(key->powers[i]), &(key->powers[(i + 1)]));
	}
}

void generic_hctr2_poly(const u8* in, const struct polyhash_key* key, uint64_t nbytes, const u8* final, be128* accumulator) {
    be128 tmp;
    int index = 0;
    int final_shift;
    size_t nblocks;
    nblocks = nbytes / POLYHASH_BLOCK_SIZE;
    while(nblocks >= NUM_PRECOMPUTE_KEYS) {
        gf128mul_lle(accumulator, (be128*)&key->powers[0]); 
        for(int i = 0; i < NUM_PRECOMPUTE_KEYS; i++) {
		    memcpy(&tmp, &in[(i + index)*POLYHASH_BLOCK_SIZE], sizeof(u128));
            reverse(&tmp);
            gf128mul_lle(&tmp, (be128*)&key->powers[i]);
            be128_xor(accumulator, accumulator, (be128*)&tmp);
        }
        index += NUM_PRECOMPUTE_KEYS;
        nblocks -= NUM_PRECOMPUTE_KEYS;
    }
    final_shift = nbytes % POLYHASH_BLOCK_SIZE == 0 ? 0 : 1;
    if(nblocks > 0 || final_shift == 1) {
        /* 0 <= NUM_PRECOMPUTE_KEYS - nblocks - final_shift < NUM_PRECOMPUTE_KEYS */
        gf128mul_lle(accumulator, (be128*)&key->powers[NUM_PRECOMPUTE_KEYS - nblocks - final_shift]);
        for(int i = 0; i < nblocks; i++) {
            memcpy(&tmp, &in[(i + index)*POLYHASH_BLOCK_SIZE], sizeof(u128));
            reverse(&tmp);
            gf128mul_lle((be128*)&tmp, (be128*)&key->powers[NUM_PRECOMPUTE_KEYS - nblocks - final_shift + i]);
            be128_xor(accumulator, accumulator, (be128*)&tmp);
        }
        index += nblocks;
        nblocks -= nblocks;
        if(final_shift == 1) {
		    memcpy(&tmp, final, sizeof(u128));
            reverse(&tmp);
            gf128mul_lle((be128*)&tmp, (be128*)&key->powers[NUM_PRECOMPUTE_KEYS - 1]);
            be128_xor(accumulator, accumulator, (be128*)&tmp);
        }
    }
} 

void polyhash_hash_tweak(const struct polyhash_key *key,
        		struct polyhash_state *state, const u8 *data,
                size_t nbytes, bool mdiv, bool simd) {
    u128 padded_final;
    state->state.b = nbytes*8*2 + (mdiv ? 2 : 3);
    state->state.a = 0;
    if(nbytes % POLYHASH_BLOCK_SIZE != 0) {
        padded_final.a = 0;
        padded_final.b = 0;
        memcpy(&padded_final, data + POLYHASH_BLOCK_SIZE*(nbytes / POLYHASH_BLOCK_SIZE), nbytes % POLYHASH_BLOCK_SIZE);
    }
    if(simd) {
        MUL(&state->state, &key->powers[NUM_PRECOMPUTE_KEYS - 1]);
        POLY(data, key, nbytes, &padded_final, &state->state);
    }
    else {
        reverse(&state->state);
        gf128mul_lle((be128*)&state->state, (be128*)&key->powers[NUM_PRECOMPUTE_KEYS - 1]);
        generic_hctr2_poly(data, key, nbytes, (u8*)&padded_final, (be128*)&state->state);
    }
}

void polyhash_hash_message(const struct polyhash_key *key,
        		struct polyhash_state *state, const u8 *data,
                size_t nbytes, bool simd) {
    u128 padded_final;
    if(nbytes % POLYHASH_BLOCK_SIZE != 0) {
        padded_final.a = 0;
        padded_final.b = 0;
        memcpy(&padded_final, data + POLYHASH_BLOCK_SIZE*(nbytes / POLYHASH_BLOCK_SIZE), nbytes % POLYHASH_BLOCK_SIZE);
        ((u8*)(&padded_final))[nbytes % POLYHASH_BLOCK_SIZE] = 0x80;
    }
    if(simd) {
        POLY(data, key, nbytes, &padded_final, &state->state);
    }
    else {
        generic_hctr2_poly(data, key, nbytes, (u8*)&padded_final, (be128*)&state->state);
    }
}

void polyhash_emit(const struct polyhash_key *key,
        struct polyhash_state * state, u8 *out, bool simd) {
    memcpy(out, &state->state, POLYHASH_BLOCK_SIZE);
    if(!simd) {
        reverse((be128*)out);
    }
}

static void _polyhash(const struct polyhash_key *key, const void *src,
		      unsigned int srclen, u8 *digest)
{
	struct polyhash_state polystate;

	polyhash_init(&polystate);
    polyhash_hash_message(key, &polystate, src, srclen, false);
	polyhash_emit(key, &polystate, digest, false);
}

static void _polyhash_simd(const struct polyhash_key *key, const void *src,
		      unsigned int srclen, u8 *digest)
{
	struct polyhash_state polystate;

	polyhash_init(&polystate);
    polyhash_hash_message(key, &polystate, src, srclen, true);
	polyhash_emit(key, &polystate, digest, true);
}

void test_hctr_polyhash(void)
{
#define ALGNAME		"HCTR-Polyhash"
#define HASH		_polyhash
#define HASH_SIMD	_polyhash_simd
#define SIMD_IMPL_NAME	"clmul"
#define KEY		struct polyhash_key
#define SETKEY		polyhash_setkey_generic
#define SETKEY_SIMD		polyhash_setkey_simd
#define KEY_BYTES	POLYHASH_KEY_SIZE
#define DIGEST_SIZE	POLYHASH_DIGEST_SIZE
#include "hash_benchmark_template.h"
}

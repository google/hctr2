/*
 * Poly1305 ε-almost-∆-universal hash function
 *
 * Note: this isn't the full Poly1305 MAC, i.e. it skips the final addition!
 *
 * Copyright (C) 2018 Google LLC
 *
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 */

#include "gf128.h"
#include "hctr-polyhash.h"

#ifdef __x86_64__
asmlinkage void clmul_polyhash_mul(ble128 * op1, const ble128 * op2);
asmlinkage void clmul_polyhash_mul_xor(const ble128 * op1, const ble128 * op2, ble128 * dst);
asmlinkage void clmul_polyhash_xor_reduction(const le128 *in, le128 *out);
#define CLMUL(X, Y) clmul_polyhash_mul(X, Y)
#define CLMUL_REDUCE_XOR(X, Y) clmul_polyhash_xor_reduction(X, Y)
#define CLMUL_XOR(X, Y, Z) clmul_polyhash_mul_xor(X, Y, Z)
#define CLMUL_STRIDE(X, Y, Z) clmul_polyhash_mul4_xor(X, Y, Z)
#define STRIDE_SIZE 4
#endif

#ifdef __aarch64__
asmlinkage void pmull_polyhash_mul(ble128 * op1, const ble128 * op2);
asmlinkage void pmull_polyhash_mul_xor(const ble128 * op1_list, const ble128 * op2_list, ble128 * dst);
asmlinkage void pmull_polyhash_mul4_xor(const ble128 * op1_list, const ble128 * op2_list, ble128 * dst);
asmlinkage void pmull_polyhash_xor_reduction(const le128 *in, le128 *out);
#define CLMUL(X, Y) pmull_polyhash_mul(X, Y)
#define CLMUL_REDUCE_XOR(X, Y) pmull_polyhash_xor_reduction(X, Y)
#define CLMUL_XOR(X, Y, Z) pmull_polyhash_mul_xor(X, Y, Z)
#define CLMUL_STRIDE(X, Y, Z) pmull_polyhash_mul4_xor(X, Y, Z)
#define STRIDE_SIZE 4
#endif

// Generate key powers in reverse order
static void polyhash_key_powers(struct polyhash_key *key)
{
    int curr_index;
	for(int i = 0; i < NUM_PRECOMPUTE_KEYS; i++) {
        curr_index = NUM_PRECOMPUTE_KEYS - 1 - i;
		memcpy(&key->powers[curr_index], &key->h, sizeof(ble128));
		if(i == 0) {
			gf128mul_ble(&(key->powers[curr_index]), &(key->h));
		}
		else {
			gf128mul_ble(&(key->powers[curr_index]), &(key->powers[(curr_index + 1)]));
		}
	}
}

void polyhash_setkey(struct polyhash_key *key, const u8 *raw_key)
{
	memcpy(&key->h, raw_key, sizeof(ble128));

	/* Precompute key powers */
	polyhash_key_powers(key);
}

/*
 * If power has been precomputed in key generation, return pointer to key power
 * Otherwise, overwrite tmp with proper power and return tmp
 */
inline const ble128 * get_key_power(const struct polyhash_key *key, const int exponent)
{
    if(exponent == 1) {
        return &(key->h);
    }
    return &(key->powers[NUM_PRECOMPUTE_KEYS - 1 - (exponent - 2)]);
}

/*
 * This function may only be called by polyhash_update_clmulni, otherwise
 * out of bounds accesses may occur.
 *
 * nbytes must be less than or equal to NUM_PRECOMPUTE_KEYS * POLYHASH_BLOCK_SIZE
 * otherwise finding key powers will reference out of bounds of the 
 * precomputed key buffer
 */
void polyhash_update_internal_generic(const struct polyhash_key *key,
        		struct polyhash_state *state, const u8 *data,
        		size_t nbytes)
{
    ble128 tmp[STRIDE_SIZE];
    u64 exponent;
    size_t nblocks;
    size_t nstrides;
    size_t partial_append;

    // last update left partial block
    if(state->partial_block_length > 0) {
        if(nbytes >= POLYHASH_BLOCK_SIZE - state->partial_block_length) {
            // we now have a full block
            partial_append = POLYHASH_BLOCK_SIZE - state->partial_block_length;
            memcpy((u8*)&(state->partial_block) + state->partial_block_length,
                    data, partial_append);
            memcpy(tmp, &key->h, POLYHASH_KEY_SIZE);
            CLMUL(&state->state, tmp);
            /* block * h^2 */
            memcpy(tmp, get_key_power(key, 2), POLYHASH_KEY_SIZE);
            gf128mul_ble(tmp, &state->partial_block);
            ble128_xor(&state->state, tmp);
            memset(&state->partial_block, 0, POLYHASH_BLOCK_SIZE);
            state->partial_block_length = 0;
        }
        else {
            partial_append = nbytes;
            memcpy((u8 *)&state->partial_block + state->partial_block_length,
                    data, partial_append);
            state->partial_block_length += partial_append;
        }
        // shift data pointer to account for partial first block
        data = data+partial_append;
        state->num_hashed_bytes += partial_append;
        nbytes -= partial_append;
        // now we can hash normally as if there was no partial block
    }
    nblocks = nbytes / POLYHASH_BLOCK_SIZE;

    // exponentiate all previously hashed blocks
    if(nblocks != 0) {
        CLMUL(&state->state, get_key_power(key, nblocks));
    }

    for(int i = 0; i < nblocks; i++) {
        exponent = (nblocks+1) - i;
        memcpy(tmp, get_key_power(key, exponent), POLYHASH_KEY_SIZE);
        gf128mul_ble(tmp, data + (i * POLYHASH_BLOCK_SIZE));
        ble128_xor(&state->state, tmp);
    }
    if(nbytes % POLYHASH_BLOCK_SIZE) {
        memcpy(&state->partial_block, data + nblocks*POLYHASH_BLOCK_SIZE, 
                nbytes % POLYHASH_BLOCK_SIZE);
        state->partial_block_length = nbytes % POLYHASH_BLOCK_SIZE;
    }

    state->num_hashed_bytes += nbytes;
}

void polyhash_update_generic(const struct polyhash_key *key,
        		struct polyhash_state *state, const u8 *data,
        		size_t nbytes)
{
    int i;
    for(i = 0; i + POLYHASH_BLOCK_SIZE*NUM_PRECOMPUTE_KEYS <= nbytes; i += POLYHASH_BLOCK_SIZE*NUM_PRECOMPUTE_KEYS) {
    	 polyhash_update_internal_generic(key, state, data + i, POLYHASH_BLOCK_SIZE*NUM_PRECOMPUTE_KEYS);
    }
    polyhash_update_internal_generic(key, state, data + i, nbytes % (POLYHASH_BLOCK_SIZE*NUM_PRECOMPUTE_KEYS));
}

void polyhash_emit_generic(const struct polyhash_key *key,
				struct polyhash_state * state, u8 *out)
{
	ble128 tmp;
    ble128 pow;
    if(state->num_hashed_bytes == 0) {
        memcpy(out, &key->h, POLYHASH_DIGEST_SIZE);
        return;
    }
    if(state->partial_block_length) {
        memcpy(&tmp, &key->h, POLYHASH_KEY_SIZE);
        CLMUL(&state->state, &tmp);
        /* block * h^2 */
        memcpy(&tmp, get_key_power(key, 2), POLYHASH_KEY_SIZE);
        gf128mul_ble(&tmp, &state->partial_block);
        ble128_xor(&state->state, &tmp);
    }
    tmp.lo = le64_to_cpu(state->num_hashed_bytes*8);
    tmp.hi = 0;
    memcpy(out, &key->h, POLYHASH_KEY_SIZE);
    gf128mul_ble((ble128*)out, &tmp);
    ble128_xor((ble128*)out, &state->state);
}

/*
 * This function may only be called by polyhash_update, otherwise
 * out of bounds accesses may occur.
 *
 * nbytes must be less than or equal to NUM_PRECOMPUTE_KEYS * POLYHASH_BLOCK_SIZE
 * otherwise finding key powers will reference out of bounds of the 
 * precomputed key buffer
 */
void polyhash_update_internal_simd(const struct polyhash_key *key,
        		struct polyhash_state *state, const u8 *data,
        		size_t nbytes)
{
    ble128 tmp[STRIDE_SIZE];
    ble128 unreduced[3];
    u64 exponent;
    size_t nblocks;
    size_t nstrides;
    size_t partial_append;

    // last update left partial block
    if(state->partial_block_length > 0) {
        if(nbytes >= POLYHASH_BLOCK_SIZE - state->partial_block_length) {
            // we now have a full block
            partial_append = POLYHASH_BLOCK_SIZE - state->partial_block_length;
            memcpy((u8*)&(state->partial_block) + state->partial_block_length,
                    data, partial_append);
            memcpy(tmp, &key->h, POLYHASH_KEY_SIZE);
            CLMUL(&state->state, tmp);
            /* block * h^2 */
            memcpy(tmp, get_key_power(key, 2), POLYHASH_KEY_SIZE);
            CLMUL(tmp, &state->partial_block);
            ble128_xor(&state->state, tmp);
            memset(&state->partial_block, 0, POLYHASH_BLOCK_SIZE);
            state->partial_block_length = 0;
        }
        else {
            partial_append = nbytes;
            memcpy((u8 *)&state->partial_block + state->partial_block_length,
                    data, partial_append);
            state->partial_block_length += partial_append;
        }
        // shift data pointer to account for partial first block
        data = data+partial_append;
        state->num_hashed_bytes += partial_append;
        nbytes -= partial_append;
        // now we can hash normally as if there was no partial block
    }
    nblocks = nbytes / POLYHASH_BLOCK_SIZE;

    // exponentiate all previously hashed blocks
    if(nblocks != 0) {
        CLMUL(&state->state, get_key_power(key, nblocks));
    }

    memset(unreduced, 0, POLYHASH_BLOCK_SIZE*3);
    nstrides = (nblocks/STRIDE_SIZE);
    for(int i = 0; i < nstrides; i++) {
        exponent = (nblocks+1) - (i * STRIDE_SIZE);
        CLMUL_STRIDE(
                data + (i * POLYHASH_BLOCK_SIZE * STRIDE_SIZE), 
                get_key_power(key, exponent), 
                unreduced
        );
    }
    for(int i = 0; i < nblocks % STRIDE_SIZE; i++) {
        int index = i + nstrides * STRIDE_SIZE;
        exponent = (nblocks+1) - index;
        CLMUL_XOR(
                data + (index * POLYHASH_BLOCK_SIZE),
                get_key_power(key, exponent),
                unreduced
        );
    }
    CLMUL_REDUCE_XOR(unreduced, &state->state);
    if(nbytes % POLYHASH_BLOCK_SIZE) {
        memcpy(&state->partial_block, data + nblocks*POLYHASH_BLOCK_SIZE, 
                nbytes % POLYHASH_BLOCK_SIZE);
        state->partial_block_length = nbytes % POLYHASH_BLOCK_SIZE;
    }

    state->num_hashed_bytes += nbytes;
}

void polyhash_update_simd(const struct polyhash_key *key,
        		struct polyhash_state *state, const u8 *data,
        		size_t nbytes)
{
    int i;
    for(i = 0; i + POLYHASH_BLOCK_SIZE*NUM_PRECOMPUTE_KEYS <= nbytes; i += POLYHASH_BLOCK_SIZE*NUM_PRECOMPUTE_KEYS) {
    	 polyhash_update_internal_simd(key, state, data + i, POLYHASH_BLOCK_SIZE*NUM_PRECOMPUTE_KEYS);
    }
    polyhash_update_internal_simd(key, state, data + i, nbytes % (POLYHASH_BLOCK_SIZE*NUM_PRECOMPUTE_KEYS));
}

void polyhash_emit_simd(const struct polyhash_key *key,
				struct polyhash_state * state, u8 *out)
{
	ble128 tmp;
    ble128 pow;
    if(state->num_hashed_bytes == 0) {
        memcpy(out, &key->h, POLYHASH_DIGEST_SIZE);
        return;
    }
    if(state->partial_block_length) {
        memcpy(&tmp, &key->h, POLYHASH_KEY_SIZE);
        CLMUL(&state->state, &tmp);
        /* block * h^2 */
        memcpy(&tmp, get_key_power(key, 2), POLYHASH_KEY_SIZE);
        CLMUL(&tmp, &state->partial_block);
        ble128_xor(&state->state, &tmp);
    }
    tmp.lo = le64_to_cpu(state->num_hashed_bytes*8);
    tmp.hi = 0;
    memcpy(out, &key->h, POLYHASH_KEY_SIZE);
    CLMUL((ble128*)out, &tmp);
    ble128_xor((ble128*)out, &state->state);
}

/* Poly1305 benchmarking */

static void _polyhash(const struct polyhash_key *key, const void *src,
		      unsigned int srclen, u8 *digest)
{
	struct polyhash_state polystate;
	ble128 out;
    int i;

	polyhash_init(&polystate);
    for(i = 0; i + POLYHASH_BLOCK_SIZE*32 <= srclen; i += POLYHASH_BLOCK_SIZE*32) {
        polyhash_update_generic(key, &polystate, src + i, POLYHASH_BLOCK_SIZE*32);
    }
    polyhash_update_generic(key, &polystate, src + i, srclen % (POLYHASH_BLOCK_SIZE*32));
	polyhash_emit_generic(key, &polystate, &out);

	memcpy(digest, &out, sizeof(out));
}

static void _polyhash_simd(const struct polyhash_key *key, const void *src,
		      unsigned int srclen, u8 *digest)
{
	struct polyhash_state polystate;
	ble128 out;
    int i;

	polyhash_init(&polystate);
    for(i = 0; i + POLYHASH_BLOCK_SIZE*32 <= srclen; i += POLYHASH_BLOCK_SIZE*32) {
        polyhash_update_simd(key, &polystate, src + i, POLYHASH_BLOCK_SIZE*32);
    }
    polyhash_update_simd(key, &polystate, src + i, srclen % (POLYHASH_BLOCK_SIZE*32));
	polyhash_emit_simd(key, &polystate, &out);

	memcpy(digest, &out, sizeof(out));
}

void test_hctr_polyhash(void)
{
#define ALGNAME		"HCTR-Polyhash"
#define HASH		_polyhash
#define HASH_SIMD	_polyhash_simd
#define SIMD_IMPL_NAME	"clmul"
#define KEY		struct polyhash_key
#define SETKEY		polyhash_setkey
#define KEY_BYTES	POLYHASH_KEY_SIZE
#define DIGEST_SIZE	POLYHASH_DIGEST_SIZE
#include "hash_benchmark_template.h"
}

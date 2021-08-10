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

#include "hctr-polyhash.h"

#ifdef __x86_64__
asmlinkage void clmul_polyhash_mul(ble128 * op1, const ble128 * op2);
#define CLMUL(X, Y) clmul_polyhash_mul(X, Y)
#endif

#ifdef __aarch64__
asmlinkage void pmull_polyhash_mul(ble128 * op1, const ble128 * op2);
#define CLMUL(X, Y) pmull_polyhash_mul(X, Y)
#endif


static void polyhash_key_powers_clmulni(struct polyhash_key *key)
{
	for(int i = 0; i < NUM_PRECOMPUTE_KEYS; i++) {
		memcpy(&key->powers[i], &key->h, sizeof(ble128));
		if(i == 0) {
			CLMUL((&key->powers)[i], &(key->h));
		}
		else {
			CLMUL(&(key->powers[i]), &(key->powers[(i-1)]));
		}
	}
}

void polyhash_setkey(struct polyhash_key *key, const u8 *raw_key)
{
	memcpy(&key->h, raw_key, sizeof(ble128));

	/* Precompute key powers */
	polyhash_key_powers_clmulni(key);
}

/*
 * nbytes must be a multiple of POLYHASH_BLOCK_SIZE
 */
void polyhash_update_clmulni(const struct polyhash_key *key,
        		struct polyhash_state *state, const u8 *data,
        		size_t nbytes)
{
    ble128 tmp;
    u64 exponent;
    ble128 pow;
    size_t nblocks;
    size_t partial_append;

    // last update left partial block
    if(state->partial_block_length > 0) {
        if(nbytes >= POLYHASH_BLOCK_SIZE - state->partial_block_length) {
            // we now have a full block
            partial_append = POLYHASH_BLOCK_SIZE - state->partial_block_length;
            memcpy((u8*)&(state->partial_block) + state->partial_block_length,
                    data, partial_append);
            memcpy(&tmp, &key->h, POLYHASH_KEY_SIZE);
            CLMUL(&state->state, &tmp);
            /* block * h^2 */
            memcpy(&tmp, &key->powers[0], POLYHASH_KEY_SIZE);
            CLMUL(&tmp, &state->partial_block);
            ble128_xor(&state->state, &tmp);
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
    if(nblocks > 1 && nblocks - 2 < NUM_PRECOMPUTE_KEYS) {
        memcpy(&tmp, &key->powers[nblocks - 2], POLYHASH_KEY_SIZE);
    }
    else if(nblocks == 1) {
        memcpy(&tmp, &key->h, POLYHASH_KEY_SIZE);
    }
    else if(nblocks > 0) {
        // this path can be avoided by hashing in batches of 32 blocks
        memcpy(&tmp, &key->h, POLYHASH_KEY_SIZE);
        for(int j = 1; j < exponent; j++) {
            CLMUL(&tmp, &key->h);
        }
    }

    if(nblocks != 0) {
        CLMUL(&state->state, &tmp);
    }

    for(int i = 0; i < nblocks; i++) {
        exponent = (nblocks+1) - i;
        memcpy(&tmp, data + (i * POLYHASH_BLOCK_SIZE), POLYHASH_BLOCK_SIZE);
        if(exponent - 2 < NUM_PRECOMPUTE_KEYS) {
            CLMUL(&tmp, &(key->powers[exponent - 2]));
            ble128_xor(&state->state, &tmp);
        } else {
            // this path can be avoided by hashing in batches of 32 blocks
            memcpy(&pow, &key->h, POLYHASH_KEY_SIZE);
            for(int j = 1; j < exponent; j++) {
                CLMUL(&pow, &key->h);
            }
            CLMUL(&tmp, &pow);
            ble128_xor(&state->state, &tmp);
        }
    }
    if(nbytes % POLYHASH_BLOCK_SIZE) {
        memcpy(&state->partial_block, data + nblocks*POLYHASH_BLOCK_SIZE, 
                nbytes % POLYHASH_BLOCK_SIZE);
        state->partial_block_length = nbytes % POLYHASH_BLOCK_SIZE;
    }

    state->num_hashed_bytes += nbytes;
}

void polyhash_emit_clmulni(const struct polyhash_key *key,
				struct polyhash_state * state, u8 *out)
{
	ble128 tmp;
    if(state->num_hashed_bytes == 0) {
        memcpy(out, &key->h, POLYHASH_DIGEST_SIZE);
        return;
    }
    if(state->partial_block_length) {
        memcpy(&tmp, &key->h, POLYHASH_KEY_SIZE);
        CLMUL(&state->state, &tmp);
        /* block * h^2 */
        memcpy(&tmp, &key->powers[0], POLYHASH_KEY_SIZE);
        CLMUL(&tmp, &state->partial_block);
        ble128_xor(&state->state, &tmp);
    }
    tmp.lo = le64_to_cpu(state->num_hashed_bytes*8);
    tmp.hi = 0;
    memcpy(out, &key->h, POLYHASH_KEY_SIZE);
    CLMUL((ble128*)out, &tmp);
    ble128_xor((ble128*)out, &state->state);
}

void polyhash_update(const struct polyhash_key *key,
        		struct polyhash_state *state, const u8 *data,
                size_t nbytes) {
    polyhash_update_clmulni(key, state, data, nbytes);
}

void polyhash_emit(const struct polyhash_key *key,
        struct polyhash_state * state, u8 *out) {
    polyhash_emit_clmulni(key, state, out);
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
        polyhash_update(key, &polystate, src + i, POLYHASH_BLOCK_SIZE*32);
    }
    polyhash_update(key, &polystate, src + i, srclen % (POLYHASH_BLOCK_SIZE*32));
	polyhash_emit(key, &polystate, &out);

	memcpy(digest, &out, sizeof(out));
}

void test_hctr_polyhash(void)
{
#define ALGNAME		"HCTR-Polyhash"
#define HASH		_polyhash
#define KEY		struct polyhash_key
#define SETKEY		polyhash_setkey
#define KEY_BYTES	POLYHASH_KEY_SIZE
#define DIGEST_SIZE	POLYHASH_DIGEST_SIZE
#include "hash_benchmark_template.h"
}

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

asmlinkage void clmul_polyhash_mul(ble128 * op1, const ble128 * op2);

static void polyhash_key_powers_clmulni(struct polyhash_key *key)
{
	for(int i = 0; i < NUM_PRECOMPUTE_KEYS; i++) {
		memcpy(&key->powers[i], &key->h, sizeof(ble128));
		if(i == 0) {
			clmul_polyhash_mul((&key->powers)[i], &(key->h));
		}
		else {
			clmul_polyhash_mul(&(key->powers[i]), &(key->powers[(i-1)]));
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
    size_t nblocks = nbytes / POLYHASH_BLOCK_SIZE;

    if(nblocks - 2 < NUM_PRECOMPUTE_KEYS) {
        memcpy(&tmp, &key->powers[nblocks - 2], POLYHASH_KEY_SIZE);
    }
    else if(nblocks == 1) {
        memcpy(&tmp, &key->h, POLYHASH_KEY_SIZE);
    }
    else if(nblocks == 0) {
        return;
    }
    else {
        // this path can be avoided by hashing in batches of 32 blocks
        memcpy(&tmp, &key->h, POLYHASH_KEY_SIZE);
        for(int j = 1; j < exponent; j++) {
            clmul_polyhash_mul(&tmp, &key->h);
        }
    }
    clmul_polyhash_mul(&state->state, &tmp);

    for(int i = 0; i < nblocks; i++) {
        exponent = (nblocks+1) - i;
        memcpy(&tmp, data + (i * nblocks), POLYHASH_BLOCK_SIZE);
        if(exponent - 2 < NUM_PRECOMPUTE_KEYS) {
            clmul_polyhash_mul(&tmp, &(key->powers[exponent - 2]));
            ble128_xor(&state->state, &tmp);
        } else {
            // this path can be avoided by hashing in batches of 32 blocks
            memcpy(&pow, &key->h, POLYHASH_KEY_SIZE);
            for(int j = 1; j < exponent; j++) {
                clmul_polyhash_mul(&pow, &key->h);
            }
            clmul_polyhash_mul(&tmp, &pow);
            ble128_xor(&state->state, &tmp);
        }
    }
    state->num_hashed_bytes += nbytes;
}

/*
 * Optionally called as the last hash round to allow for end blocks that
 * are not multiples of POLYHASH_BLOCK_SIZE
 *
 * Equivalent to polyhash_update if nbytes is a multiple of POLYHASH_BLOCK_SIZE
 *
 * nbytes is not required to be a multiple of POLYHASH_BLOCK_SIZE
 */
void polyhash_tail_clmulni(const struct polyhash_key *key,
        		struct polyhash_state *state, const u8 *data,
                size_t nbytes) {
    size_t nblocks = nbytes / POLYHASH_BLOCK_SIZE;
    ble128 tmp;
    ble128 padded_block;

    if(nblocks > 0) {
        polyhash_update_clmulni(key, state, data, nblocks * POLYHASH_BLOCK_SIZE);
    }
    if(nbytes % POLYHASH_BLOCK_SIZE) {
        memcpy(&tmp, &key->h, POLYHASH_KEY_SIZE);
    	clmul_polyhash_mul(&state->state, &tmp);

        /* block * h^2 */
        memcpy(&tmp, &key->powers[0], POLYHASH_KEY_SIZE);
        memset(&padded_block, 0, POLYHASH_BLOCK_SIZE);
        memcpy(&padded_block, data + nblocks, nbytes % POLYHASH_BLOCK_SIZE);
		clmul_polyhash_mul(&tmp, &padded_block);
        ble128_xor(&state->state, &tmp);

        for(int i = 0; i < 16; i++) {
            printf("%02hhx", ((u8 *)&state->state)[i]);
        }
        printf("\n");
    }
    state->num_hashed_bytes += nbytes;
}

void polyhash_emit_clmulni(const struct polyhash_key *key,
				struct polyhash_state * state, u8 *out)
{
	ble128 tmp;
    if(state->num_hashed_bytes == 0) {
        memcpy(out, &key->h, POLYHASH_DIGEST_SIZE);
    }
    tmp.lo = 0;
    tmp.hi = be64_to_cpu(state->num_hashed_bytes*8);
    memcpy(out, &key->h, POLYHASH_KEY_SIZE);
    clmul_polyhash_mul((ble128*)out, &tmp);
    ble128_xor((ble128*)out, &state->state);
}

/* Poly1305 benchmarking */

static void _polyhash(const struct polyhash_key *key, const void *src,
		      unsigned int srclen, u8 *digest, bool simd)
{
	struct polyhash_state state;
	ble128 out;

	polyhash_init(&state);
	polyhash_emit_generic(key, src, srclen, out);

	memcpy(digest, &out, sizeof(out));
}

void test_polyhash(void)
{
}

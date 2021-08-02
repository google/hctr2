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

/* data should be padded with zeroes to be a multiple of 16 bytes */
void polyhash_emit_clmulni(const struct polyhash_key *key,
			     const u8 *data, size_t nblocks, u8 *out)
{
    ble128 tmp;
    u64 exponent;
    ble128 pow;
    if(nblocks == 0) {
        memcpy(out, &key->h, POLYHASH_DIGEST_SIZE);
    }
    tmp.lo = 0;
    tmp.hi = be64_to_cpu(nblocks*8*POLYHASH_BLOCK_SIZE);
    memcpy(out, &key->h, POLYHASH_KEY_SIZE);
    clmul_polyhash_mul((ble128*)out, &tmp);

    for(int i = 0; i < nblocks; i++) {
        exponent = (nblocks+1) - i;
        memcpy(&tmp, data + (i * nblocks), POLYHASH_BLOCK_SIZE);
        if(exponent - 2 < NUM_PRECOMPUTE_KEYS) {
            clmul_polyhash_mul(&tmp, &(key->powers[exponent - 2]));
            ble128_xor((ble128*)out, &tmp);
        } else {
            // only hit this path if encrypting >4096 byte blocks with HCTR
            pow;
            memcpy(&pow, &key->h, POLYHASH_KEY_SIZE);
            for(int j = 1; j < exponent; j++) {
                clmul_polyhash_mul(&pow, &key->h);
            }
            clmul_polyhash_mul(&tmp, &pow);
            ble128_xor((ble128*)out, &tmp);
        }
    }
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

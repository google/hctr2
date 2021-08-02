/*
 * Copyright (C) 2018 Google LLC
 *
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 */
#pragma once

#include "util.h"

#define POLYHASH_BLOCK_SIZE	16
#define POLYHASH_DIGEST_SIZE	16
#define POLYHASH_KEY_SIZE	16
#define NUM_PRECOMPUTE_KEYS	32

struct polyhash_key {
	ble128 h;

	/*
	 * h^2 ... h^33
         * for efficient encryption of 512 byte plaintext
	 */
	ble128 powers[NUM_PRECOMPUTE_KEYS];
};

struct polyhash_state {
	ble128 state;
    size_t num_hashed_bytes;
};

void polyhash_setkey(struct polyhash_key *key, const u8 *raw_key);

static inline void polyhash_init(struct polyhash_state *state)
{
	memset(&state->state, 0, sizeof(state->state));
    state->num_hashed_bytes = 0;
}

void polyhash_generic(const struct polyhash_key *key,
			     struct polyhash_state *state,
			     const u8 *data, size_t nbytes);

void polyhash_update_clmulni(const struct polyhash_key *key,
        struct polyhash_state *state, const u8 *data,
        size_t nbytes);

static inline void polyhash(const struct polyhash_key *key,
				   struct polyhash_state *state,
				   const void *data, size_t nbytes, bool simd)
{
	polyhash_generic(key, state, data, nbytes);
}

/*
 * HCTR polyhash
 *
 * Copyright 2021 Google LLC<nhuck@google.com>
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 *
 * Author: Nathan Huckleberry <nhuck@google.com>
 */
#pragma once

#include "util.h"

#define POLYHASH_BLOCK_SIZE	16
#define POLYHASH_DIGEST_SIZE	16
#define POLYHASH_KEY_SIZE	16
#define NUM_PRECOMPUTE_KEYS	64

struct polyhash_key {
	ble128 h;

	/*
	 * h^2 ... h^N
         * for efficient encryption of 512 byte plaintext
	 */
	ble128 powers[NUM_PRECOMPUTE_KEYS];
};

struct polyhash_state {
	ble128 state;
    ble128 partial_block;
    size_t partial_block_length;
    size_t num_hashed_bytes;
};

void polyhash_setkey(struct polyhash_key *key, const u8 *raw_key);

static inline void polyhash_init(struct polyhash_state *state)
{
	memset(&state->state, 0, sizeof(state->state));
	memset(&state->partial_block, 0, sizeof(state->partial_block));
    state->num_hashed_bytes = 0;
    state->partial_block_length = 0;
}

void polyhash_update(const struct polyhash_key *key,
        		struct polyhash_state *state, const u8 *data,
        		size_t nbytes, bool simd);

void polyhash_emit(const struct polyhash_key *key,
				struct polyhash_state * state, u8 *out, bool simd);

void polyhash_update_simd(const struct polyhash_key *key,
        		struct polyhash_state *state, const u8 *data,
        		size_t nbytes);

void polyhash_emit_simd(const struct polyhash_key *key,
				struct polyhash_state * state, u8 *out);

void polyhash_update_generic(const struct polyhash_key *key,
        		struct polyhash_state *state, const u8 *data,
        		size_t nbytes);

void polyhash_emit_generic(const struct polyhash_key *key,
				struct polyhash_state * state, u8 *out);

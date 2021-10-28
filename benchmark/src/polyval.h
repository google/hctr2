/*
 * Copyright 2021 Google LLC
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 */
#pragma once

#include "util.h"
#include "gf128.h"
#include "polyval-asm.h"

#define POLYVAL_BLOCK_SIZE 16
#define POLYVAL_DIGEST_SIZE 16
#define POLYVAL_KEY_SIZE 16

struct polyval_key {
	/*
	 * h^N, ..., h in reverse order
	 */
	u128 powers[NUM_PRECOMPUTE_KEYS];
};

struct polyval_state {
	u128 state;
};

void reverse_bytes(be128 *a);

static inline void polyval_init(struct polyval_state *state)
{
	memset(state, 0, sizeof(*state));
}

void polyval_setkey(struct polyval_key *key, const u8 *raw_key, bool simd);

void polyval_update(struct polyval_state *state, const struct polyval_key *key,
		    const u8 *in, size_t nbytes,
		    const u8 final_block[POLYVAL_BLOCK_SIZE], bool simd);

void polyval_emit(struct polyval_state *state, u8 out[POLYVAL_DIGEST_SIZE],
		  bool simd);

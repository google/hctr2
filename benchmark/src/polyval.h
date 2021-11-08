/*
 * Copyright 2021 Google LLC
 *
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

/*
 * GF(2^128) elements are represented differently depending on whether
 * we're using the accelerated POLYVAL implementation or the generic
 * GHASH-like implementation.
 */
struct polyval_key {
	union key {
		/*
		 * Array of montgomery-form GF(2^128) field elements
		 * stored in big-little endian.
		 *
		 * The GF(2^128) element x^128 is represented in memory as
		 * [0x00 0x00 0x00 0x00 | 0x00 0x00 0x00 0x00 |
		 *  0x00 0x00 0x00 0x00 | 0x00 0x00 0x00 0x80 ]
		 * The GF(2^128) element 1 is represented in memory as
		 * [0x01 0x00 0x00 0x00 | 0x00 0x00 0x00 0x00 |
		 *  0x00 0x00 0x00 0x00 | 0x00 0x00 0x00 0x00 ]
		 *
		 * The array contains the GF(2^128) elements h^n .. h^1
		 * in decreasing order of degree.
		 */
		ble128 simd_powers[NUM_PRECOMPUTE_KEYS];
		/*
		 * GF(2^128) element h stored in little-little endian.
		 *
		 * The GF(2^128) element x^128 is represented in memory as
		 * [0x00 0x00 0x00 0x00 | 0x00 0x00 0x00 0x00 |
		 *  0x00 0x00 0x00 0x00 | 0x00 0x00 0x00 0x01 ]
		 * The GF(2^128) element 1 is represented in memory as
		 * [0x80 0x00 0x00 0x00 | 0x00 0x00 0x00 0x00 |
		 *  0x00 0x00 0x00 0x00 | 0x00 0x00 0x00 0x00 ]
		 *
		 * We don't need any higher powers of h since
		 * the generic implementation is not parallelized.
		 */
		be128 generic_h;
	} key;
};

struct polyval_state {
	union state {
		ble128 simd_state;
		be128 generic_state;
	} state;
};

void reverse_bytes(be128 *a);

static inline void polyval_init(struct polyval_state *state)
{
	memset(state, 0, sizeof(*state));
}

void polyval_setkey(struct polyval_key *key, const u8 *raw_key, bool simd);

void polyval_update(struct polyval_state *state, const struct polyval_key *key,
		    const u8 *in, size_t nblocks, bool simd);

void polyval_emit(struct polyval_state *state, u8 out[POLYVAL_DIGEST_SIZE],
		  bool simd);

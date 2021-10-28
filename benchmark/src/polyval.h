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

/*
 * Polynomials are represented differently depending on whether
 * we're using the accelerated POLYVAL implementation or the generic
 * GHASH-like implementation.
 */
union polyval_key {
	/*
	 * Array of montgomery-form polynomials stored in big-little endian.
	 *
	 * The polynomial x^128 is represented in memory as
	 * [0x00 0x00 0x00 0x00 | 0x00 0x00 0x00 0x00 |
	 *  0x00 0x00 0x00 0x00 | 0x00 0x00 0x00 0x80 ]
	 * The polynomial 1 is represented in memory as
	 * [0x01 0x00 0x00 0x00 | 0x00 0x00 0x00 0x00 |
	 *  0x00 0x00 0x00 0x00 | 0x00 0x00 0x00 0x00 ]
	 *
	 * The array contains the polynomials h^n .. h^1
	 * in decreasing order of degree.
	 */
	ble128 simd_powers[NUM_PRECOMPUTE_KEYS];
	/*
	 * Array of polynomials stored in little-little endian.
	 *
	 * The polynomial x^128 is represented in memory as
	 * [0x00 0x00 0x00 0x00 | 0x00 0x00 0x00 0x00 |
	 *  0x00 0x00 0x00 0x00 | 0x00 0x00 0x00 0x01 ]
	 * The polynomial 1 is represented in memory as
	 * [0x80 0x00 0x00 0x00 | 0x00 0x00 0x00 0x00 |
	 *  0x00 0x00 0x00 0x00 | 0x00 0x00 0x00 0x00 ]
	 *
	 * The array contains the polynomials h^n .. h^1
	 * in decreasing order of degree.
	 */
	be128 generic_powers[NUM_PRECOMPUTE_KEYS];
};

union polyval_state {
	ble128 simd_state;
	be128 generic_state;
};

void reverse_bytes(be128 *a);

static inline void polyval_init(union polyval_state *state)
{
	memset(state, 0, sizeof(*state));
}

void polyval_setkey(union polyval_key *key, const u8 *raw_key, bool simd);

void polyval_update(union polyval_state *state, const union polyval_key *key,
		    const u8 *in, size_t nbytes,
		    const u8 final_block[POLYVAL_BLOCK_SIZE], bool simd);

void polyval_emit(union polyval_state *state, u8 out[POLYVAL_DIGEST_SIZE],
		  bool simd);

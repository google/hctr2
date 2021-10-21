/*
 * Copyright 2021 Google LLC
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 */
#pragma once

#include "util.h"
#include "gf128.h"

#define POLYVAL_BLOCK_SIZE 16
#define POLYVAL_DIGEST_SIZE 16
#define POLYVAL_KEY_SIZE 16
#define NUM_PRECOMPUTE_KEYS 64

struct polyval_key {
	/*
	 * h^N, ..., h in reverse order
	 */
	u128 powers[NUM_PRECOMPUTE_KEYS];
};

#ifdef __x86_64__
asmlinkage void clmul_polyval(const u8 *in,
				    const struct polyval_key *keys,
				    uint64_t nbytes, const u128 *final,
				    u128 *accumulator);
asmlinkage void clmul_polyval_mul(u128 *op1, const u128 *op2);
#define POLYVAL clmul_polyval
#define MUL clmul_polyval_mul
#endif
#ifdef __aarch64__
asmlinkage void pmull_polyval(const u8 *in,
				    const struct polyval_key *keys,
				    uint64_t nbytes, const u128 *final,
				    u128 *accumulator);
asmlinkage void pmull_polyval_mul(u128 *op1, const u128 *op2);
#define POLYVAL pmull_polyval
#define MUL pmull_polyval_mul
#endif

struct polyval_state {
	u128 state;
};

void reverse_bytes(be128 *a);

void polyval_setkey(struct polyval_key *key, const u8 *raw_key,
		      bool simd);

void polyval_generic(const u8 *in, const struct polyval_key *key,
			uint64_t nbytes, const u8 *final, be128 *accumulator);

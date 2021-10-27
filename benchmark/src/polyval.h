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
#if !defined(__x86_64__) && !defined(__aarch64__)
    #error Unsupported architecture.
#endif

struct polyval_state {
	u128 state;
};

void reverse_bytes(be128 *a);

void polyval_init(struct polyval_state *state);

void polyval_setkey(struct polyval_key *key, const u8 *raw_key,
		      bool simd);

void polyval_update(struct polyval_state *state, const struct polyval_key *key, 
        const u8 *in, size_t nbytes, const u8 final_block[POLYVAL_BLOCK_SIZE], 
        bool simd);

void polyval_emit(struct polyval_state *state, u8 out[POLYVAL_DIGEST_SIZE], bool simd);

/*
 * Copyright 2021 Google LLC
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 */
#pragma once

#include "util.h"

#define POLYHASH_BLOCK_SIZE 16
#define POLYHASH_DIGEST_SIZE 16
#define POLYHASH_KEY_SIZE 16
#define NUM_PRECOMPUTE_KEYS 64

struct polyhash_key {
	/*
	 * h^N, ..., h in reverse order
	 */
	u128 powers[NUM_PRECOMPUTE_KEYS];
	u128 tweaklen_part[2];
};

struct polyhash_state {
	u128 state;
};

void polyhash_setup_generic(struct polyhash_key *key, const u8 *raw_key,
			    size_t tweak_len);
void polyhash_setup_simd(struct polyhash_key *key, const u8 *raw_key,
			 size_t tweak_len);

void polyhash_hash_tweak(const struct polyhash_key *key,
			 struct polyhash_state *state, const u8 *data,
			 size_t nbytes, bool mdiv, bool simd);

void polyhash_hash_message(const struct polyhash_key *key,
			   struct polyhash_state *state, const u8 *data,
			   size_t nbytes, bool simd);

void polyhash_emit(const struct polyhash_key *key, struct polyhash_state *state,
		   u8 *out, bool simd);

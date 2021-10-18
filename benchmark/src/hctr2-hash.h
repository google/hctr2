/*
 * Copyright 2021 Google LLC
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 */
#pragma once

#include "util.h"

#define HCTR2_HASH_BLOCK_SIZE 16
#define HCTR2_HASH_DIGEST_SIZE 16
#define HCTR2_HASH_KEY_SIZE 16
#define NUM_PRECOMPUTE_KEYS 64

struct hctr2_hash_key {
	/*
	 * h^N, ..., h in reverse order
	 */
	u128 powers[NUM_PRECOMPUTE_KEYS];
	u128 tweaklen_part[2];
};

struct hctr2_hash_state {
	u128 state;
};

void hctr2_hash_setup(struct hctr2_hash_key *key, const u8 *raw_key,
		      size_t tweak_len, bool simd);

void hctr2_hash_hash_tweak(const struct hctr2_hash_key *key,
			   struct hctr2_hash_state *state, const u8 *data,
			   size_t nbytes, bool mdiv, bool simd);

void hctr2_hash_hash_message(const struct hctr2_hash_key *key,
			     struct hctr2_hash_state *state, const u8 *data,
			     size_t nbytes, bool simd);

void hctr2_hash_emit(const struct hctr2_hash_key *key,
		     struct hctr2_hash_state *state, u8 *out, bool simd);

/*
 * Copyright 2021 Google LLC
 *
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 */
#pragma once

#include "testvec.h"

struct hctr2_testvec {
	struct testvec_buffer key;
	struct testvec_buffer tweak;
	struct testvec_buffer plaintext;
	struct testvec_buffer ciphertext;
};

extern const struct hctr2_testvec hctr2_aes128_tv[];
extern const size_t hctr2_aes128_tv_count;
extern const struct hctr2_testvec hctr2_aes192_tv[];
extern const size_t hctr2_aes192_tv_count;
extern const struct hctr2_testvec hctr2_aes256_tv[];
extern const size_t hctr2_aes256_tv_count;

/*
 * Copyright 2021 Google LLC
 *
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 */

#include "aes.h"
#include "aes_linux.h"
#include "util.h"

#define XCTR_IV_SIZE 16
#define XCTR_BLOCK_SIZE 16

void xctr_crypt(const struct aes_ctx *ctx, u8 *dst, const u8 *src,
		size_t nbytes, const u8 *iv, bool simd);

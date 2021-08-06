/*
 * HCTR encryption mode
 *
 * Copyright (C) 2021 Google LLC
 *
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 */

#include "aes.h"
#include "aes_linux.h"
#include "util.h"

#define CTR_IV_SIZE	16
#define CTR_BLOCK_SIZE 16
#define CTR_KEY_SIZE 32

void hctr_ctr_setkey(struct aes_ctx *ctx, const u8 *key);

void hctr_ctr_crypt(const struct aes_ctx *ctx, u8 *dst, const u8 *src,
		       size_t nbytes, const u8 *iv);

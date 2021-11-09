/*
 * Copyright 2018 Google LLC
 *
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 */
#pragma once

#include "util.h"
#include "aes_linux.h"

struct aes_ctx {
	struct crypto_aes_ctx aes_ctx;
} __attribute__((aligned(32)));

void aes_setkey(struct aes_ctx *ctx, const u8 *key, int key_len);
void aes_encrypt(const struct aes_ctx *ctx, u8 *out, const u8 *in, bool simd);
void aes_decrypt(const struct aes_ctx *ctx, u8 *out, const u8 *in, bool simd);

static inline int aes_nrounds(const struct aes_ctx *ctx)
{
	/*
	 * AES-128: 6 + 16 / 4 = 10 rounds
	 * AES-192: 6 + 24 / 4 = 12 rounds
	 * AES-256: 6 + 32 / 4 = 14 rounds
	 */
	return 6 + ctx->aes_ctx.key_length / 4;
}

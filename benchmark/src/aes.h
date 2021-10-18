/*
 * Copyright (C) 2018 Google LLC
 *
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 */
#pragma once

#include "util.h"
#include "aes_linux.h"

struct aes_ctx {
#ifdef __arm__ /* for aes-neonbs */
	int rounds;
	u8 pad[12];
	u8 rk[13 * (8 * AES_BLOCK_SIZE) + 32];
#endif
	struct crypto_aes_ctx aes_ctx;
} __attribute__((aligned(32)));

void aes128_setkey(struct aes_ctx *ctx, const u8 *key);
void aes256_setkey(struct aes_ctx *ctx, const u8 *key);
void aes_encrypt(const struct aes_ctx *ctx, u8 *out, const u8 *in, bool simd);
void aes_decrypt(const struct aes_ctx *ctx, u8 *out, const u8 *in, bool simd);

#ifdef __aarch64__
void ce_aes_ecb_encrypt(u8 out[], u8 const in[], u8 const rk[], int rounds,
			int blocks);
void ce_aes_ecb_decrypt(u8 out[], u8 const in[], u8 const rk[], int rounds,
			int blocks);
#endif

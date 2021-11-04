/*
 * AES block cipher (glue code)
 *
 * Copyright (C) 2018 Google LLC
 *
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 */

#include "aes.h"

/*
 * Notes on chosen AES implementations:
 *
 * We only include implementations that are constant-time, or at least include
 * some hardening measures against cache-timing attacks.  By necessity we
 * tolerate implementations that try to be "constant-time" by prefetching the
 * lookup table(s) into cache, though this isn't guaranteed to be sufficient.
 *
 * For the portable implementation, we use aes_ti.c from Linux.  This is a
 * staightforward AES implementation that uses the 256-byte S-box and 256-byte
 * inverse S-box.  Each is prefetched before use.
 */

void aes_setkey(struct aes_ctx *ctx, const u8 *key, int key_len)
{
	int err;

	err = aesti_set_key(&ctx->aes_ctx, key, key_len);
	ASSERT(err == 0);
}

void aes_encrypt_generic(const struct aes_ctx *ctx, u8 *out, const u8 *in)
{
	aesti_encrypt(&ctx->aes_ctx, out, in);
}

void aes_decrypt_generic(const struct aes_ctx *ctx, u8 *out, const u8 *in)
{
	aesti_decrypt(&ctx->aes_ctx, out, in);
}

void aes_encrypt_simd(const struct aes_ctx *ctx, u8 *out, const u8 *in)
{
#ifdef __x86_64__
	aesni_ecb_enc(&ctx->aes_ctx, out, in, AES_BLOCK_SIZE);
#endif
#ifdef __aarch64__
	int rounds = 6 + ctx->aes_ctx.key_length / 4;
	ce_aes_ecb_encrypt(out, in, (u8 *)ctx->aes_ctx.key_enc, rounds, 1);
#endif
#if !defined(__x86_64__) && !defined(__aarch64__)
#error Unsupported architecture.
#endif
}

void aes_decrypt_simd(const struct aes_ctx *ctx, u8 *out, const u8 *in)
{
#ifdef __x86_64__
	aesni_ecb_dec(&ctx->aes_ctx, out, in, AES_BLOCK_SIZE);
#endif
#ifdef __aarch64__
	int rounds = 6 + ctx->aes_ctx.key_length / 4;
	ce_aes_ecb_decrypt(out, in, (u8 *)ctx->aes_ctx.key_dec, rounds, 1);
#endif
#if !defined(__x86_64__) && !defined(__aarch64__)
#error Unsupported architecture.
#endif
}

void aes_encrypt(const struct aes_ctx *ctx, u8 *out, const u8 *in, bool simd)
{
	if (simd) {
		aes_encrypt_simd(ctx, out, in);
	} else {
		aes_encrypt_generic(ctx, out, in);
	}
}

void aes_decrypt(const struct aes_ctx *ctx, u8 *out, const u8 *in, bool simd)
{
	if (simd) {
		aes_decrypt_simd(ctx, out, in);
	} else {
		aes_decrypt_generic(ctx, out, in);
	}
}

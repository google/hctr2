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
 *
 * For 32-bit ARM: for AES-XTS we use the NEON bit-sliced implementation from
 * Linux; this is fastest and also constant-time.  For single blocks, we use the
 * ARM scalar AES cipher from Linux, which uses a 1024-byte table for
 * encryption, and a 1024-byte and a 256-byte table for decryption.  Even after
 * prefetching these tables, this implementation is much faster than aes_ti.c.
 * The 1024-byte tables combine the SubBytes (or InvSubBytes) and MixColumns (or
 * InvMixColumns) steps.  Normally 4096-byte tables would be needed for this,
 * but since rotations are "free" in ARM assembly only the first part is needed.
 */

static void aes_setkey(struct aes_ctx *ctx, const u8 *key, int key_len)
{
	int err;

	err = aesti_set_key(&ctx->aes_ctx, key, key_len);
	ASSERT(err == 0);
}

void aes128_setkey(struct aes_ctx *ctx, const u8 *key)
{
	aes_setkey(ctx, key, AES_KEYSIZE_128);
}

void aes256_setkey(struct aes_ctx *ctx, const u8 *key)
{
	aes_setkey(ctx, key, AES_KEYSIZE_256);
}

void aes_encrypt(const struct aes_ctx *ctx, u8 *out, const u8 *in)
{
	aesti_encrypt(&ctx->aes_ctx, out, in);
}

void aes_decrypt(const struct aes_ctx *ctx, u8 *out, const u8 *in)
{
	aesti_decrypt(&ctx->aes_ctx, out, in);
}

/*
 * XTS encryption
 *
 * Copyright 2021 Google LLC
 *
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 */

#include "aes.h"
#include "aes_linux.h"

#define XTS_BLOCK_SIZE 16
#define BLOCKCIPHER_KEY_SIZE 32
#define XTS_KEY_SIZE BLOCKCIPHER_KEY_SIZE * 2

struct aes_xts_ctx {
	struct aes_ctx crypt_ctx;
	struct aes_ctx tweak_ctx;
};

void xts_setkey(struct aes_xts_ctx *ctx, const u8 *key, size_t key_len)
{
	aes_setkey(&ctx->crypt_ctx, key, key_len);
	aes_setkey(&ctx->tweak_ctx, key + BLOCKCIPHER_KEY_SIZE, key_len);
}


#ifdef __x86_64__
asmlinkage void aesni_xts_encrypt(const struct crypto_aes_ctx *ctx, u8 *dst,
				  const u8 *src, unsigned int len,
				  const le128 *iv);
asmlinkage void aesni_xts_decrypt(const struct crypto_aes_ctx *ctx, u8 *dst,
				  const u8 *src, unsigned int len,
				  const le128 *iv);
#endif
#ifdef __aarch64__
asmlinkage void ce_aes_xts_encrypt(u8 out[], u8 const in[], u8 const rk1[],
				   int rounds, int bytes, u8 const rk2[],
				   const u8 iv[], int first);
asmlinkage void ce_aes_xts_decrypt(u8 out[], u8 const in[], u8 const rk1[],
				   int rounds, int bytes, u8 const rk2[],
				   const u8 iv[], int first);
#endif

static void xts_encrypt_simd(const struct aes_xts_ctx *ctx, u8 *dst,
			     const u8 *src, size_t nbytes, u8 *iv)
{
#ifdef __x86_64__
	le128 alpha;
	aesni_ecb_enc(&ctx->tweak_ctx.aes_ctx, (u8 *)&alpha, iv,
		      XTS_BLOCK_SIZE);
	aesni_xts_encrypt(&ctx->crypt_ctx.aes_ctx, dst, src, nbytes, &alpha);
#endif
#ifdef __aarch64__
	int rounds = 6 + ctx->tweak_ctx.aes_ctx.key_length / 4;
	ce_aes_xts_encrypt(dst, src, (u8 *)&ctx->tweak_ctx.aes_ctx.key_enc,
			   rounds, nbytes,
			   (u8 *)&ctx->crypt_ctx.aes_ctx.key_enc, iv, true);
#endif
}

static void xts_decrypt_simd(const struct aes_xts_ctx *ctx, u8 *dst,
			     const u8 *src, size_t nbytes, u8 *iv)
{
#ifdef __x86_64__
	le128 alpha;
	aesni_ecb_enc(&ctx->tweak_ctx.aes_ctx, (u8 *)&alpha, iv,
		      XTS_BLOCK_SIZE);
	aesni_xts_decrypt(&ctx->crypt_ctx.aes_ctx, dst, src, nbytes, &alpha);
#endif
#ifdef __aarch64__
	int rounds = 6 + ctx->tweak_ctx.aes_ctx.key_length / 4;
	ce_aes_xts_decrypt(dst, src, (u8 *)&ctx->tweak_ctx.aes_ctx.key_dec,
			   rounds, nbytes,
			   (u8 *)&ctx->crypt_ctx.aes_ctx.key_enc, iv, true);
#endif
}

static void xts_aes128_setkey(struct aes_xts_ctx *ctx, const u8 *key)
{
	xts_setkey(ctx, key, AES_KEYSIZE_128);
}

static void xts_aes192_setkey(struct aes_xts_ctx *ctx, const u8 *key)
{
	xts_setkey(ctx, key, AES_KEYSIZE_192);
}

static void xts_aes256_setkey(struct aes_xts_ctx *ctx, const u8 *key)
{
	xts_setkey(ctx, key, AES_KEYSIZE_256);
}

void test_xts(void)
{
#define ALGNAME "AES-128-XTS"
#define KEY_BYTES AES_KEYSIZE_128 * 2
#define IV_BYTES 16
#define KEY struct aes_xts_ctx
#define SETKEY_SIMD xts_aes128_setkey
#define SIMD_IMPL_NAME "simd"
#define ENCRYPT_SIMD xts_encrypt_simd
#define DECRYPT_SIMD xts_decrypt_simd
#include "cipher_benchmark_template.h"

#define ALGNAME "AES-192-XTS"
#define KEY_BYTES AES_KEYSIZE_192 * 2
#define IV_BYTES 16
#define KEY struct aes_xts_ctx
#define SETKEY_SIMD xts_aes192_setkey
#define SIMD_IMPL_NAME "simd"
#define ENCRYPT_SIMD xts_encrypt_simd
#define DECRYPT_SIMD xts_decrypt_simd
#include "cipher_benchmark_template.h"

#define ALGNAME "AES-256-XTS"
#define KEY_BYTES AES_KEYSIZE_256 * 2
#define IV_BYTES 16
#define KEY struct aes_xts_ctx
#define SETKEY_SIMD xts_aes256_setkey
#define SIMD_IMPL_NAME "simd"
#define ENCRYPT_SIMD xts_encrypt_simd
#define DECRYPT_SIMD xts_decrypt_simd
#include "cipher_benchmark_template.h"
}

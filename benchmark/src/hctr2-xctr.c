/*
 * Copyright 2021 Google LLC
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 */

#include "aes.h"
#include "aes_linux.h"
#include "hctr2-xctr.h"

void xctr_setkey(struct aes_ctx *ctx, const u8 *key)
{
	aes256_setkey(ctx, key);
}


#ifdef __x86_64__
asmlinkage void aes_xctr_enc_256_avx_by8(const u8 *in, const u8 *iv,
					 const struct aes_ctx *key, u8 *out,
					 size_t num_bytes);
#endif
#ifdef __aarch64__
asmlinkage void ce_aes_xctr_encrypt(u8 out[], u8 const in[], u8 const rk[],
				    int rounds, int bytes, const u8 ctr[]);
#endif

void xctr_crypt_simd(const struct aes_ctx *ctx, u8 *dst, const u8 *src,
		     size_t nbytes, const u8 *iv)
{
	u128 extra;
	size_t offset;
#ifdef __x86_64__
	aes_xctr_enc_256_avx_by8(src, iv, ctx, dst, nbytes);
#endif
#ifdef __aarch64__
	ce_aes_xctr_encrypt(dst, src, (u8 *)&ctx->aes_ctx.key_enc, 14, nbytes,
			    iv);
#endif

	if (nbytes % XCTR_BLOCK_SIZE != 0) {
		offset = (nbytes / XCTR_BLOCK_SIZE) * XCTR_BLOCK_SIZE;
		extra.a = 0;
		extra.b = cpu_to_le64(nbytes / XCTR_BLOCK_SIZE) + 1;
		xor(&extra, &extra, iv, XCTR_BLOCK_SIZE);

		aes_encrypt(ctx, (u8 *)&extra, (u8 *)&extra, true);

		xor(&dst[offset], (u8 *)&extra, &src[offset],
		    nbytes % XCTR_BLOCK_SIZE);
	}
}

void xctr_crypt_generic(const struct aes_ctx *ctx, u8 *dst, const u8 *src,
			size_t nbytes, const u8 *iv)
{
	int i;
	int nblocks;
	size_t offset;
	u128 ctr;

	nblocks = nbytes / XCTR_BLOCK_SIZE;
	for (i = 0; i < nblocks; i++) {
		ctr.a = 0;
		ctr.b = cpu_to_le64(i + 1);
		xor(&ctr, &ctr, iv, XCTR_BLOCK_SIZE);
		aes_encrypt(ctx, &dst[i * XCTR_BLOCK_SIZE], (u8 *)&ctr, false);
		xor(&dst[i * XCTR_BLOCK_SIZE], &dst[i * XCTR_BLOCK_SIZE],
		    &src[i * XCTR_BLOCK_SIZE], XCTR_BLOCK_SIZE);
	}

	if (nbytes % XCTR_BLOCK_SIZE != 0) {
		offset = (nbytes / XCTR_BLOCK_SIZE) * XCTR_BLOCK_SIZE;
		ctr.a = 0;
		ctr.b = cpu_to_le64(nbytes / XCTR_BLOCK_SIZE) + 1;
		xor(&ctr, &ctr, iv, XCTR_BLOCK_SIZE);
		aes_encrypt(ctx, (u8 *)&ctr, (u8 *)&ctr, false);
		xor(&dst[offset], (u8 *)&ctr, &src[offset],
		    nbytes % XCTR_BLOCK_SIZE);
	}
}

void xctr_crypt(const struct aes_ctx *ctx, u8 *dst, const u8 *src,
		size_t nbytes, const u8 *iv, bool simd)
{
	if (simd) {
		xctr_crypt_simd(ctx, dst, src, nbytes, iv);
	} else {
		xctr_crypt_generic(ctx, dst, src, nbytes, iv);
	}
}

void test_xctr(void)
{
#define ALGNAME "XCTR"
#define KEY_BYTES XCTR_KEY_SIZE
#define IV_BYTES XCTR_IV_SIZE
#define KEY struct aes_ctx
#define SETKEY xctr_setkey
#define SETKEY_SIMD xctr_setkey
#define ENCRYPT xctr_crypt_generic
#define DECRYPT xctr_crypt_generic
#define SIMD_IMPL_NAME "simd"
#define ENCRYPT_SIMD xctr_crypt_simd
#define DECRYPT_SIMD xctr_crypt_simd
#include "cipher_benchmark_template.h"
}

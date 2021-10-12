/*
 * HCTR-XCTR encryption mode
 *
 * Copyright 2021 Google LLC
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 * 
 * Author: Nathan Huckleberry <nhuck@google.com>
 */

#include "aes.h"
#include "aes_linux.h"
#include "hctr-xctr.h"

void hctr_ctr_setkey(struct aes_ctx *ctx, const u8 *key)
{
    aes256_setkey(ctx, key);
}


#ifdef __x86_64__
asmlinkage void aes_ctr_enc_256_avx_by8(const u8 * in, const u8 * iv, 
        		const u8 * key, u8 * out, size_t num_bytes);
#endif
#ifdef __aarch64__
asmlinkage void ce_aes_hctr_ctr_encrypt(u8 out[], u8 const in[], u8 const rk[], int rounds,
                int bytes, u8 ctr[]);
#endif

void hctr_ctr_crypt(const struct aes_ctx *ctx, u8 *dst, const u8 *src,
        size_t nbytes, const u8 *iv, bool simd) {
    if(simd) {
        hctr_ctr_crypt_simd(ctx, dst, src, nbytes, iv);
    }
    else {
        hctr_ctr_crypt_generic(ctx, dst, src, nbytes, iv);
    }
}

void hctr_ctr_crypt_simd(const struct aes_ctx *ctx, u8 *dst, const u8 *src,
		       size_t nbytes, const u8 *iv)
{
    u128 extra;
    u64 ctr;
    size_t offset;
#ifdef __x86_64__
    aes_ctr_enc_256_avx_by8(src, iv, ctx, dst, nbytes);
#endif
#ifdef __aarch64__
    ce_aes_hctr_ctr_encrypt(dst, src, ctx, 14, nbytes, iv);
#endif

    if(nbytes % XCTR_BLOCK_SIZE != 0) {
        offset = (nbytes / XCTR_BLOCK_SIZE) * XCTR_BLOCK_SIZE;
        extra.a = 0;
        extra.b = cpu_to_le64(nbytes / XCTR_BLOCK_SIZE) + 1;
        xor(&extra, &extra, iv, XCTR_BLOCK_SIZE);

#ifdef __x86_64__
        aesni_ecb_enc(ctx, &extra, &extra, XCTR_BLOCK_SIZE);
#endif
#ifdef __aarch64__
        ce_aes_ecb_encrypt(&extra, &extra, ctx->aes_ctx.key_enc, 14, 1);
#endif

        xor(&dst[offset], (u8*)&extra, &src[offset], nbytes % XCTR_BLOCK_SIZE);
    }
}

void hctr_ctr_crypt_generic(const struct aes_ctx *ctx, u8 *dst, const u8 *src,
		       size_t nbytes, const u8 *iv)
{
    int i;
    int nblocks;
    size_t offset;
    u128 ctr;

    nblocks = nbytes / XCTR_BLOCK_SIZE;
    for(i = 0; i < nblocks; i++) {
        ctr.a = 0;
        ctr.b = cpu_to_le64(i+1);
        xor(&ctr, &ctr, iv, XCTR_BLOCK_SIZE);
        aes_encrypt(ctx, &dst[i * XCTR_BLOCK_SIZE], (u8*)&ctr);
        xor(&dst[i * XCTR_BLOCK_SIZE], &dst[i * XCTR_BLOCK_SIZE], &src[i * XCTR_BLOCK_SIZE], XCTR_BLOCK_SIZE);
    }
    
    if(nbytes % XCTR_BLOCK_SIZE != 0) {
        offset = (nbytes / XCTR_BLOCK_SIZE) * XCTR_BLOCK_SIZE;
        ctr.a = 0;
        ctr.b = cpu_to_le64(nbytes / XCTR_BLOCK_SIZE) + 1;
        xor(&ctr, &ctr, iv, XCTR_BLOCK_SIZE);
        aes_encrypt(ctx, (u8*)&ctr, (u8*)&ctr);
        xor(&dst[offset], (u8*)&ctr, &src[offset], nbytes % XCTR_BLOCK_SIZE);
    }
}

void test_hctr_ctr(void)
{
#define ALGNAME		"HCTR-CTR"
#define KEY_BYTES	XCTR_KEY_SIZE
#define IV_BYTES	XCTR_IV_SIZE
#define KEY		struct aes_ctx
#define SETKEY		hctr_ctr_setkey
#define SETKEY_SIMD		hctr_ctr_setkey
#define ENCRYPT		hctr_ctr_crypt_generic
#define DECRYPT		hctr_ctr_crypt_generic
#define SIMD_IMPL_NAME "simd"
#define ENCRYPT_SIMD	hctr_ctr_crypt_simd
#define DECRYPT_SIMD	hctr_ctr_crypt_simd
#include "cipher_benchmark_template.h"
}

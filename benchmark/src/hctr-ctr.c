/*
 * HCTR-XCTR encryption mode
 *
 * Copyright (C) 2021 Google LLC. <nhuck@google.com>
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 * 
 * Author: Nathan Huckleberry <nhuck@google.com>
 */

#include "aes.h"
#include "aes_linux.h"
#include "hctr-ctr.h"

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
                int bytes, u8 ctr[], u8 finalbuf[]);
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

// Assume nbytes is a multiple of BLOCK_SIZE
void hctr_ctr_crypt_simd(const struct aes_ctx *ctx, u8 *dst, const u8 *src,
		       size_t nbytes, const u8 *iv)
{
#ifdef __x86_64__
    aes_ctr_enc_256_avx_by8(src, iv, ctx, dst, nbytes);
#endif
#ifdef __aarch64__
    u8 extra[CTR_BLOCK_SIZE];
    ce_aes_hctr_ctr_encrypt(dst, src, ctx, 14, nbytes, iv, extra);
#endif
}

void hctr_ctr_crypt_generic(const struct aes_ctx *ctx, u8 *dst, const u8 *src,
		       size_t nbytes, const u8 *iv)
{
    int i;
    int nblocks;
    ble128 ctr;
    ctr.lo = 0;
    ctr.hi = 0;

    nblocks = nbytes / CTR_BLOCK_SIZE;
    for(i = 0; i < nblocks; i++) {
        ctr.lo = i+1;
        ctr.hi = 0;
        ble128_xor(&ctr,(ble128*)iv);
        aes_encrypt(ctx, &dst[i * CTR_BLOCK_SIZE], (u8*)&ctr);
        //aesni_ecb_enc(&ctx->aes_ctx, &dst[i * CTR_BLOCK_SIZE], &ctr, CTR_BLOCK_SIZE);
        ble128_xor((ble128*)&dst[i * CTR_BLOCK_SIZE], (ble128*)&src[i * CTR_BLOCK_SIZE]);
    }
}

void test_hctr_ctr(void)
{
#define ALGNAME		"HCTR-CTR"
#define KEY_BYTES	CTR_KEY_SIZE
#define IV_BYTES	CTR_IV_SIZE
#define KEY		struct aes_ctx
#define SETKEY		hctr_ctr_setkey
#define ENCRYPT		hctr_ctr_crypt_generic
#define DECRYPT		hctr_ctr_crypt_generic
#define SIMD_IMPL_NAME "simd"
#define ENCRYPT_SIMD	hctr_ctr_crypt_simd
#define DECRYPT_SIMD	hctr_ctr_crypt_simd
#include "cipher_benchmark_template.h"
}

/*
 * HCTR encryption mode
 *
 * Copyright (C) 2021 Google LLC
 *
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 */

#include "hctr-ctr.h"

void hctr_ctr_setkey(struct aes_ctx *ctx, const u8 *key)
{
    aesti_expand_key(ctx, key, 256);
}


#ifdef __x86_64__
asmlinkage void aes_ctr_enc_256_avx_by8(const u8 * in, const u8 * iv, 
        		const u8 * key, u8 * out, size_t num_bytes);
#endif
#ifdef __aarch64__
asmlinkage void ce_aes_hctr_ctr_encrypt(u8 out[], u8 const in[], u8 const rk[], int rounds,
                int bytes, u8 ctr[], u8 finalbuf[]);
#endif

// Assume nbytes is a multiple of BLOCK_SIZE
void hctr_ctr_crypt(const struct aes_ctx *ctx, u8 *dst, const u8 *src,
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

void test_hctr_ctr(void)
{
#define ALGNAME		"HCTR-CTR"
#define KEY_BYTES	CTR_KEY_SIZE
#define IV_BYTES	CTR_IV_SIZE
#define KEY		struct aes_ctx
#define SETKEY		hctr_ctr_setkey
#define ENCRYPT		hctr_ctr_crypt
#define DECRYPT		hctr_ctr_crypt
#include "cipher_benchmark_template.h"
}

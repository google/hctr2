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

asmlinkage void aes_ctr_enc_256_avx_by8(const u8 * in, const u8 * iv, 
        		const u8 * key, u8 * out, size_t num_bytes);

// Assume nbytes is a multiple of BLOCK_SIZE
void hctr_ctr_crypt(const struct aes_ctx *ctx, u8 *dst, const u8 *src,
		       size_t nbytes, const u8 *iv)
{
    aes_ctr_enc_256_avx_by8(src, iv, ctx, dst, nbytes);
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

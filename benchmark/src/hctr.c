/*
 * HCTR encryption mode
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
#include "hctr-polyhash.h"
#include "testvec.h"
#include "util.h"

#define HCTR_DEFAULT_TWEAK_LEN	32
#define BLOCKCIPHER_BLOCK_SIZE		16

/* Size of the hash key (H_K) in bytes */
#define BLOCKCIPHER_KEY_SIZE 32
#define HCTR_HASH_KEY_SIZE	POLYHASH_KEY_SIZE
#define HCTR_KEY_SIZE BLOCKCIPHER_KEY_SIZE + POLYHASH_KEY_SIZE

struct hctr_ctx {
	struct aes_ctx aes_ctx;
	unsigned int default_tweak_len;
    struct polyhash_key polyhash_key;
};

/*
 * Let K_H be the 128-bit hash key and K_E be the 256-bit AES key
 * Assume:
 *     K = K_H || K_E
 */
void hctr_setkey(struct hctr_ctx *ctx, const u8 *key)
{
    polyhash_setkey(&ctx->polyhash_key, key);
	aesti_expand_key(&ctx->aes_ctx, key + HCTR_HASH_KEY_SIZE, BLOCKCIPHER_KEY_SIZE);
    ctx->default_tweak_len = HCTR_DEFAULT_TWEAK_LEN;
}

/*
 * Assume that nbytes is a multiple of BLOCKCIPHER_BLOCK_SIZE
 */
void hctr_crypt(const struct hctr_ctx *ctx, u8 *dst, const u8 *src,
		       size_t nbytes, const u8 *tweak, size_t tweak_len, bool encrypt, bool simd)
{
    struct polyhash_state polystate;
    u8 digest[POLYHASH_DIGEST_SIZE];
    u8 MM[BLOCKCIPHER_BLOCK_SIZE];
    u8 CC[BLOCKCIPHER_BLOCK_SIZE];
    u8 S[BLOCKCIPHER_BLOCK_SIZE];
    const u8 * M;
    const u8 * N;
    u8 * C;
    u8 * D;
    size_t M_bytes;
    size_t N_bytes;
    size_t i;
	
    ASSERT(nbytes >= BLOCKCIPHER_BLOCK_SIZE);
    M_bytes = BLOCKCIPHER_BLOCK_SIZE;
    N_bytes = nbytes - M_bytes;
    M = src;
    N = src + BLOCKCIPHER_BLOCK_SIZE;
    C = dst;
    D = dst + BLOCKCIPHER_BLOCK_SIZE;

    polyhash_init(&polystate);
    polyhash_update(&ctx->polyhash_key, &polystate, N, N_bytes, simd);
    polyhash_update(&ctx->polyhash_key, &polystate, tweak, tweak_len, simd);
    polyhash_emit(&ctx->polyhash_key, &polystate, (u8 *)&digest, simd);

    xor(&MM, M, digest, BLOCKCIPHER_BLOCK_SIZE);
    
#ifdef __x86_64__
    if(encrypt) {
        aesni_ecb_enc(&ctx->aes_ctx, &CC, MM, BLOCKCIPHER_BLOCK_SIZE);
    }
    else {
        aesni_ecb_dec(&ctx->aes_ctx, &CC, MM, BLOCKCIPHER_BLOCK_SIZE);
    }
#endif
#ifdef __aarch64__
    if(encrypt) {
        ce_aes_ecb_encrypt(&CC, MM, &ctx->aes_ctx.aes_ctx.key_enc, 14, 1);
    }
    else {
        ce_aes_ecb_decrypt(&CC, MM, &ctx->aes_ctx.aes_ctx.key_dec, 14, 1);
    }
#endif
    
    xor(&S, &MM, &CC, BLOCKCIPHER_BLOCK_SIZE);

    hctr_ctr_crypt(&ctx->aes_ctx, D, N, N_bytes, &S, simd);

    polyhash_init(&polystate);
    polyhash_update(&ctx->polyhash_key, &polystate, D, N_bytes, simd);
    polyhash_update(&ctx->polyhash_key, &polystate, tweak, tweak_len, simd);
    polyhash_emit(&ctx->polyhash_key, &polystate, (u8 *)&digest, simd);

    xor(C, &CC, digest, BLOCKCIPHER_BLOCK_SIZE);
}

void hctr_encrypt_generic(const struct hctr_ctx *ctx, u8 *dst, const u8 *src,
        size_t nbytes, const u8 *tweak) {
    hctr_crypt(ctx, dst, src, nbytes, tweak, ctx->default_tweak_len, true, false);
}

void hctr_decrypt_generic(const struct hctr_ctx *ctx, u8 *dst, const u8 *src,
        size_t nbytes, const u8 *tweak) {
    hctr_crypt(ctx, dst, src, nbytes, tweak, ctx->default_tweak_len, false, false);
}

void hctr_encrypt_simd(const struct hctr_ctx *ctx, u8 *dst, const u8 *src,
        size_t nbytes, const u8 *tweak) {
    hctr_crypt(ctx, dst, src, nbytes, tweak, ctx->default_tweak_len, true, true);
}

void hctr_decrypt_simd(const struct hctr_ctx *ctx, u8 *dst, const u8 *src,
        size_t nbytes, const u8 *tweak) {
    hctr_crypt(ctx, dst, src, nbytes, tweak, ctx->default_tweak_len, false, true);
}


void test_hctr(void)
{
#define ALGNAME		"HCTR"
#define KEY_BYTES	HCTR_KEY_SIZE
#define IV_BYTES	HCTR_DEFAULT_TWEAK_LEN
#define KEY		struct hctr_ctx
#define SETKEY		hctr_setkey
#define ENCRYPT		hctr_encrypt_generic
#define DECRYPT		hctr_decrypt_generic
#define ENCRYPT_SIMD		hctr_encrypt_simd
#define DECRYPT_SIMD		hctr_decrypt_simd
#define SIMD_IMPL_NAME "simd"
#include "cipher_benchmark_template.h"
}

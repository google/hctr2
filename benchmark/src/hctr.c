/*
 * HCTR encryption mode
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
#include "hctr-polyhash.h"
#include "testvec.h"
#include "util.h"

#define HCTR_DEFAULT_TWEAK_LEN	32
#define BLOCKCIPHER_BLOCK_SIZE		16

/* Size of the hash key (H_K) in bytes */
#define BLOCKCIPHER_KEY_SIZE 32
#define HCTR_KEY_SIZE BLOCKCIPHER_KEY_SIZE

struct hctr_ctx {
    struct aes_ctx aes_ctx;
    unsigned int default_tweak_len;
    struct polyhash_key polyhash_key;
    u8 L[BLOCKCIPHER_BLOCK_SIZE];
};

void hctr_setkey_generic(struct hctr_ctx *ctx, const u8 *key)
{
    u8 h[BLOCKCIPHER_BLOCK_SIZE];
    u128 buf;
    aesti_expand_key(&ctx->aes_ctx, key, BLOCKCIPHER_KEY_SIZE);
    ctx->default_tweak_len = HCTR_DEFAULT_TWEAK_LEN;

    buf.a = 0;
    buf.b = 0;
    aes_encrypt(&ctx->aes_ctx, &h, (u8*)&buf);
    buf.b = cpu_to_le64(1);
    aes_encrypt(&ctx->aes_ctx, &ctx->L, (u8*)&buf);

    polyhash_setkey_generic(&ctx->polyhash_key, &h);
}

void hctr_setkey_simd(struct hctr_ctx *ctx, const u8 *key)
{
    u8 h[BLOCKCIPHER_BLOCK_SIZE];
    u128 buf;
    aesti_expand_key(&ctx->aes_ctx, key, BLOCKCIPHER_KEY_SIZE);
    ctx->default_tweak_len = HCTR_DEFAULT_TWEAK_LEN;
    
    buf.a = 0;
    buf.b = 0;
    #ifdef __x86_64__
        aesni_ecb_enc(&ctx->aes_ctx, &h, &buf, XCTR_BLOCK_SIZE);
    #endif
    #ifdef __aarch64__
        ce_aes_ecb_encrypt(&h, &buf, &ctx->aes_ctx.aes_ctx.key_enc, 14, 1);
    #endif
    buf.b = cpu_to_le64(1);
    #ifdef __x86_64__
        aesni_ecb_enc(&ctx->aes_ctx, &ctx->L, &buf, XCTR_BLOCK_SIZE);
    #endif
    #ifdef __aarch64__
        ce_aes_ecb_encrypt(&ctx->L, &buf, &ctx->aes_ctx.aes_ctx.key_enc, 14, 1);
    #endif
    
    polyhash_setkey_simd(&ctx->polyhash_key, &h);
}

/*
 * Assume that nbytes is a multiple of BLOCKCIPHER_BLOCK_SIZE
 *
 * TODO: Modify XCTR code to allow for non-multiple plaintexts
 */
void hctr_crypt(const struct hctr_ctx *ctx, u8 *dst, const u8 *src,
		       size_t nbytes, const u8 *tweak, size_t tweak_len, bool encrypt, bool simd)
{
    struct polyhash_state polystate1;
    struct polyhash_state polystate2;
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

    polyhash_init(&polystate1);
    polyhash_hash_tweak(&ctx->polyhash_key, &polystate1, tweak, tweak_len, N_bytes % POLYHASH_BLOCK_SIZE == 0, simd);
    memcpy(&polystate2, &polystate1, sizeof(polystate1));
    polyhash_hash_message(&ctx->polyhash_key, &polystate1, N, N_bytes, simd);
    polyhash_emit(&ctx->polyhash_key, &polystate1, (u8 *)&digest, simd);
    
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
    xor(&S, &ctx->L, &S, BLOCKCIPHER_BLOCK_SIZE);

    hctr_ctr_crypt(&ctx->aes_ctx, D, N, N_bytes, &S, simd);
    
    polyhash_hash_message(&ctx->polyhash_key, &polystate2, D, N_bytes, simd);
    polyhash_emit(&ctx->polyhash_key, &polystate2, (u8 *)&digest, simd);
    
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
#define SETKEY		hctr_setkey_generic
#define SETKEY_SIMD		hctr_setkey_simd
#define ENCRYPT		hctr_encrypt_generic
#define DECRYPT		hctr_decrypt_generic
#define ENCRYPT_SIMD		hctr_encrypt_simd
#define DECRYPT_SIMD		hctr_decrypt_simd
#define SIMD_IMPL_NAME "simd"
#include "cipher_benchmark_template.h"
}

/*
 * HCTR encryption mode
 *
 * Copyright (C) 2021 Google LLC
 *
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 */

#include "aes.h"
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
	struct aes_ctx aesti_ctx;
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
	aes256_setkey(&ctx->aesti_ctx, key + HCTR_HASH_KEY_SIZE);
    ctx->default_tweak_len = HCTR_DEFAULT_TWEAK_LEN;
}

asmlinkage void aes_ctr_enc_256_avx_by8(const u8 * in, const u8 * iv, 
        		const u8 * key, u8 * out, size_t num_bytes);

/*
 * Assume that nbytes is a multiple of BLOCKCIPHER_BLOCK_SIZE
 */
void hctr_crypt(const struct hctr_ctx *ctx, u8 *dst, const u8 *src,
		       size_t nbytes, const u8 *tweak, size_t tweak_len, bool encrypt)
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
    // Hash 32 blocks each iteration to ensure fast path
    for(i = 0; i + POLYHASH_BLOCK_SIZE*32 <= N_bytes; i += POLYHASH_BLOCK_SIZE*32) {
    	 polyhash_update(&ctx->polyhash_key, &polystate, N + i, POLYHASH_BLOCK_SIZE*32);
    }
    polyhash_update(&ctx->polyhash_key, &polystate, N + i, N_bytes % (POLYHASH_BLOCK_SIZE*32));
    polyhash_update(&ctx->polyhash_key, &polystate, tweak, tweak_len/8);
    polyhash_emit(&ctx->polyhash_key, &polystate, (u8 *)&digest);

    xor(&MM, M, digest, BLOCKCIPHER_BLOCK_SIZE);
    
    if(encrypt) {
        aes_encrypt(&ctx->aesti_ctx, &CC, MM);
    }
    else {
        aes_decrypt(&ctx->aesti_ctx, &CC, MM);
    }
    
    xor(&S, &MM, &CC, BLOCKCIPHER_BLOCK_SIZE);

    aes_ctr_enc_256_avx_by8(N, &S, &ctx->aes_ctx, D, N_bytes);

    polyhash_init(&polystate);
    // Hash 32 blocks each iteration to ensure fast path
    for(i = 0; i + POLYHASH_BLOCK_SIZE*32 <= N_bytes; i += POLYHASH_BLOCK_SIZE*32) {
    	 polyhash_update(&ctx->polyhash_key, &polystate, D + i, POLYHASH_BLOCK_SIZE*32);
    }
    polyhash_update(&ctx->polyhash_key, &polystate, D + i, N_bytes % (POLYHASH_BLOCK_SIZE*32));
    polyhash_update(&ctx->polyhash_key, &polystate, tweak, tweak_len/8);
    polyhash_emit(&ctx->polyhash_key, &polystate, (u8 *)&digest);

    xor(C, &CC, digest, BLOCKCIPHER_BLOCK_SIZE);
}

void _hctr_encrypt(const struct hctr_ctx *ctx, u8 *dst, const u8 *src,
        size_t nbytes, const u8 *tweak, size_t tweak_len) {
    hctr_crypt(ctx, dst, src, nbytes, tweak, tweak_len, true);
}

void _hctr_decrypt(const struct hctr_ctx *ctx, u8 *dst, const u8 *src,
        size_t nbytes, const u8 *tweak, size_t tweak_len) {
    hctr_crypt(ctx, dst, src, nbytes, tweak, tweak_len, false);
}

void hctr_encrypt(const struct hctr_ctx *ctx, u8 *dst, const u8 *src,
        size_t nbytes, const u8 *tweak) {
    _hctr_encrypt(ctx, dst, src, nbytes, tweak, ctx->default_tweak_len);
}

void hctr_decrypt(const struct hctr_ctx *ctx, u8 *dst, const u8 *src,
        size_t nbytes, const u8 *tweak) {
    _hctr_decrypt(ctx, dst, src, nbytes, tweak, ctx->default_tweak_len);
}



void test_hctr(void)
{
#define ALGNAME		"HCTR"
#define KEY_BYTES	HCTR_KEY_SIZE
#define IV_BYTES	HCTR_DEFAULT_TWEAK_LEN
#define KEY		struct hctr_ctx
#define SETKEY		hctr_setkey
#define ENCRYPT		hctr_encrypt
#define DECRYPT		hctr_decrypt
#include "cipher_benchmark_template.h"
}

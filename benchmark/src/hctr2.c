/*
 * Copyright 2021 Google LLC
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 */

#include "aes.h"
#include "aes_linux.h"
#include "hctr2-xctr.h"
#include "hctr2-hash.h"
#include "testvec.h"
#include "util.h"

#define HCTR2_DEFAULT_TWEAK_LEN 16
#define BLOCKCIPHER_BLOCK_SIZE 16

/* Size of the hash key (H_K) in bytes */
#define BLOCKCIPHER_KEY_SIZE 32
#define HCTR2_KEY_SIZE BLOCKCIPHER_KEY_SIZE

struct hctr2_ctx {
	struct aes_ctx aes_ctx;
	unsigned int default_tweak_len;
	struct hctr2_hash_key hctr2_hash_key;
	u8 L[BLOCKCIPHER_BLOCK_SIZE];
};

void hctr2_setkey(struct hctr2_ctx *ctx, const u8 *key, bool simd)
{
	u8 h[BLOCKCIPHER_BLOCK_SIZE];
	u128 buf;
	aesti_expand_key(&ctx->aes_ctx.aes_ctx, key, BLOCKCIPHER_KEY_SIZE);
	ctx->default_tweak_len = HCTR2_DEFAULT_TWEAK_LEN;

	buf.a = 0;
	buf.b = 0;
	aes_encrypt(&ctx->aes_ctx, (u8 *)&h, (u8 *)&buf, simd);
	buf.b = cpu_to_le64(1);
	aes_encrypt(&ctx->aes_ctx, (u8 *)&ctx->L, (u8 *)&buf, simd);

	hctr2_hash_setup(&ctx->hctr2_hash_key, (u8 *)&h,
			       ctx->default_tweak_len, simd);
}

void hctr2_change_tweak_len(struct hctr2_ctx *ctx,
				    const size_t tweak_len, bool simd)
{
	u8 h[BLOCKCIPHER_BLOCK_SIZE];
	u128 buf;
	buf.a = 0;
	buf.b = 0;
	aes_encrypt(&ctx->aes_ctx, (u8 *)&h, (u8 *)&buf, simd);
	hctr2_hash_setup(&ctx->hctr2_hash_key, (u8 *)&h, tweak_len, simd);
}

void hctr2_crypt(const struct hctr2_ctx *ctx, u8 *dst, const u8 *src,
		 size_t nbytes, const u8 *tweak, size_t tweak_len, bool encrypt,
		 bool simd)
{
	struct hctr2_hash_state polystate1;
	struct hctr2_hash_state polystate2;
	u8 digest[HCTR2_HASH_DIGEST_SIZE];
	u8 MM[BLOCKCIPHER_BLOCK_SIZE];
	u8 UU[BLOCKCIPHER_BLOCK_SIZE];
	u8 S[BLOCKCIPHER_BLOCK_SIZE];
	const u8 *M;
	const u8 *N;
	u8 *U;
	u8 *V;
	size_t M_bytes;
	size_t N_bytes;

	ASSERT(nbytes >= BLOCKCIPHER_BLOCK_SIZE);
	M_bytes = BLOCKCIPHER_BLOCK_SIZE;
	N_bytes = nbytes - M_bytes;
	M = src;
	N = src + BLOCKCIPHER_BLOCK_SIZE;
	U = dst;
	V = dst + BLOCKCIPHER_BLOCK_SIZE;


	hctr2_hash_hash_tweak(&ctx->hctr2_hash_key, &polystate1, tweak, tweak_len,
			    N_bytes % HCTR2_HASH_BLOCK_SIZE == 0, simd);
	memcpy(&polystate2, &polystate1, sizeof(polystate1));
	hctr2_hash_hash_message(&ctx->hctr2_hash_key, &polystate1, N, N_bytes,
			      simd);
	hctr2_hash_emit(&ctx->hctr2_hash_key, &polystate1, (u8 *)&digest, simd);

	xor(&MM, M, digest, BLOCKCIPHER_BLOCK_SIZE);

    if(encrypt) {
        aes_encrypt(&ctx->aes_ctx, (u8 *)&UU, MM, simd);
    }
    else {
        aes_decrypt(&ctx->aes_ctx, (u8 *)&UU, MM, simd);
    }

	xor(&S, &MM, &UU, BLOCKCIPHER_BLOCK_SIZE);
	xor(&S, &ctx->L, &S, BLOCKCIPHER_BLOCK_SIZE);

	hctr2_ctr_crypt(&ctx->aes_ctx, V, N, N_bytes, (u8 *)&S, simd);

	hctr2_hash_hash_message(&ctx->hctr2_hash_key, &polystate2, V, N_bytes,
			      simd);
	hctr2_hash_emit(&ctx->hctr2_hash_key, &polystate2, (u8 *)&digest, simd);

	xor(U, &UU, digest, BLOCKCIPHER_BLOCK_SIZE);
}

void hctr2_setkey_generic(struct hctr2_ctx *ctx, const u8 *key) {
    hctr2_setkey(ctx, key, false);
}

void hctr2_setkey_simd(struct hctr2_ctx *ctx, const u8 *key) {
    hctr2_setkey(ctx, key, true);
}

void hctr2_encrypt_generic(const struct hctr2_ctx *ctx, u8 *dst, const u8 *src,
			   size_t nbytes, const u8 *tweak)
{
	hctr2_crypt(ctx, dst, src, nbytes, tweak, ctx->default_tweak_len, true,
		    false);
}

void hctr2_decrypt_generic(const struct hctr2_ctx *ctx, u8 *dst, const u8 *src,
			   size_t nbytes, const u8 *tweak)
{
	hctr2_crypt(ctx, dst, src, nbytes, tweak, ctx->default_tweak_len, false,
		    false);
}

void hctr2_encrypt_simd(const struct hctr2_ctx *ctx, u8 *dst, const u8 *src,
			size_t nbytes, const u8 *tweak)
{
	hctr2_crypt(ctx, dst, src, nbytes, tweak, ctx->default_tweak_len, true,
		    true);
}

void hctr2_decrypt_simd(const struct hctr2_ctx *ctx, u8 *dst, const u8 *src,
			size_t nbytes, const u8 *tweak)
{
	hctr2_crypt(ctx, dst, src, nbytes, tweak, ctx->default_tweak_len, false,
		    true);
}

#include "hctr2_testvecs.h"

static void test_hctr2_testvec(const struct hctr2_testvec *v, bool simd)
{
	size_t len = v->plaintext.len;
	u8 ptext[len];
	u8 ctext[len];
	struct hctr2_ctx ctx;

	ASSERT(v->key.len == HCTR2_KEY_SIZE);
	ASSERT(v->plaintext.len >= BLOCKCIPHER_BLOCK_SIZE);
	ASSERT(v->ciphertext.len == v->plaintext.len);

	hctr2_setkey(&ctx, v->key.data, simd);
	hctr2_change_tweak_len(&ctx, v->tweak.len, simd);
	hctr2_crypt(&ctx, (u8 *)&ctext, v->plaintext.data, v->plaintext.len,
		    v->tweak.data, v->tweak.len, true, simd);
	ASSERT(!memcmp(ctext, v->ciphertext.data, len));
	hctr2_crypt(&ctx, (u8 *)&ptext, (u8 *)&ctext, v->plaintext.len,
		    v->tweak.data, v->tweak.len, false, simd);
	ASSERT(!memcmp(ptext, v->plaintext.data, len));
}

static void test_hctr2_testvecs(void)
{
	size_t i;

	for (i = 0; i < hctr2_aes256_tv_count; i++) {
		test_hctr2_testvec(&hctr2_aes256_tv[i], false);
		test_hctr2_testvec(&hctr2_aes256_tv[i], true);
	}
}


void test_hctr2(void)
{
	test_hctr2_testvecs();
#define ALGNAME "HCTR2"
#define KEY_BYTES HCTR2_KEY_SIZE
#define IV_BYTES HCTR2_DEFAULT_TWEAK_LEN
#define KEY struct hctr2_ctx
#define SETKEY hctr2_setkey_generic
#define SETKEY_SIMD hctr2_setkey_simd
#define ENCRYPT hctr2_encrypt_generic
#define DECRYPT hctr2_decrypt_generic
#define ENCRYPT_SIMD hctr2_encrypt_simd
#define DECRYPT_SIMD hctr2_decrypt_simd
#define SIMD_IMPL_NAME "simd"
#include "cipher_benchmark_template.h"
}

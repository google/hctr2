/*
 * Copyright 2021 Google LLC
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 */

#include "aes.h"
#include "aes_linux.h"
#include "hctr2-xctr.h"
#include "polyval.h"
#include "hctr2_testvecs.h"
#include "testvec.h"
#include "util.h"

#define HCTR2_DEFAULT_TWEAK_LEN 16
#define BLOCKCIPHER_BLOCK_SIZE 16

struct hctr2_ctx {
	struct aes_ctx aes_ctx;
	unsigned int default_tweak_len;
	struct polyval_key polyval_key;
	u8 L[BLOCKCIPHER_BLOCK_SIZE];
	struct polyval_state initial_states[2];
};

/*
 * Precomputes the first block of the polynomial hash function. This block is
 * fixed for any message with the same key and tweak length.
 *
 * The two computed states are used as the polynomial hash function's initial state.
 */
void hctr2_change_tweak_len(struct hctr2_ctx *ctx, const size_t tweak_len, bool simd)
{
	u128 tmp;
	polyval_init(&ctx->initial_states[0]);
	tmp.b = tweak_len * 8 * 2 + 3;
	tmp.a = 0;
	polyval_update(&ctx->initial_states[0], &ctx->polyval_key, (u8*)&tmp, 16, NULL, simd);
	
	polyval_init(&ctx->initial_states[1]);
	tmp.b = tweak_len * 8 * 2 + 2;
	tmp.a = 0;
	polyval_update(&ctx->initial_states[1], &ctx->polyval_key, (u8*)&tmp, 16, NULL, simd);
}

void hctr2_setkey(struct hctr2_ctx *ctx, const u8 *key, size_t key_len, bool simd)
{
	u8 h[BLOCKCIPHER_BLOCK_SIZE];
	u128 buf;
	aesti_expand_key(&ctx->aes_ctx.aes_ctx, key, key_len);
	ctx->default_tweak_len = HCTR2_DEFAULT_TWEAK_LEN;

	buf.a = 0;
	buf.b = 0;
	aes_encrypt(&ctx->aes_ctx, (u8 *)&h, (u8 *)&buf, simd);
	buf.b = cpu_to_le64(1);
	aes_encrypt(&ctx->aes_ctx, (u8 *)&ctx->L, (u8 *)&buf, simd);

	polyval_setkey(&ctx->polyval_key, (u8 *)&h, simd);
	hctr2_change_tweak_len(ctx, ctx->default_tweak_len, simd);
}

static void hctr2_hash_tweak(const struct hctr2_ctx *ctx,
			   struct polyval_state *state, const u8 *data,
			   size_t nbytes, bool simd)
{
	u128 padded_final;
	if (nbytes % POLYVAL_BLOCK_SIZE != 0) {
		padded_final.a = 0;
		padded_final.b = 0;
		memcpy(&padded_final,
		       data
			       + POLYVAL_BLOCK_SIZE
					 * (nbytes / POLYVAL_BLOCK_SIZE),
		       nbytes % POLYVAL_BLOCK_SIZE);
	}
    polyval_update(state, &ctx->polyval_key, data, nbytes, &padded_final, simd);
}

static void hctr2_hash_message(const struct hctr2_ctx *ctx,
			     struct polyval_state *state, const u8 *data,
			     size_t nbytes, bool simd)
{
	u128 padded_final;
	if (nbytes % POLYVAL_BLOCK_SIZE != 0) {
		padded_final.a = 0;
		padded_final.b = 0;
		memcpy(&padded_final,
		       data
			       + POLYVAL_BLOCK_SIZE
					 * (nbytes / POLYVAL_BLOCK_SIZE),
		       nbytes % POLYVAL_BLOCK_SIZE);
		((u8 *)(&padded_final))[nbytes % POLYVAL_BLOCK_SIZE] = 0x01;
	}
    polyval_update(state, &ctx->polyval_key, data, nbytes, &padded_final, simd);
}

void hctr2_crypt(const struct hctr2_ctx *ctx, u8 *dst, const u8 *src,
		 size_t nbytes, const u8 *tweak, size_t tweak_len, bool encrypt,
		 bool simd)
{
	struct polyval_state polystate1;
	struct polyval_state polystate2;
	u8 digest[POLYVAL_DIGEST_SIZE];
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

    // Pick the appropriate precomputed first block based on whether 
    // the message divides the block size.
	bool mdiv = N_bytes % POLYVAL_BLOCK_SIZE == 0;
	memcpy(&polystate1, &ctx->initial_states[mdiv ? 1 : 0],
	       sizeof(struct polyval_state));

    // Since the tweak is the same for both hashes, save the state
    // for later to avoid re-computing the same partial hash.
	hctr2_hash_tweak(ctx, &polystate1, tweak,
			      tweak_len, simd);
	memcpy(&polystate2, &polystate1, sizeof(polystate1));
	hctr2_hash_message(ctx, &polystate1, N, N_bytes,
				simd);
	polyval_emit(&polystate1, (u8 *)&digest, simd);

	xor(&MM, M, digest, BLOCKCIPHER_BLOCK_SIZE);

	if (encrypt) {
		aes_encrypt(&ctx->aes_ctx, (u8 *)&UU, MM, simd);
	} else {
		aes_decrypt(&ctx->aes_ctx, (u8 *)&UU, MM, simd);
	}

	xor(&S, &MM, &UU, BLOCKCIPHER_BLOCK_SIZE);
	xor(&S, &ctx->L, &S, BLOCKCIPHER_BLOCK_SIZE);

	xctr_crypt(&ctx->aes_ctx, V, N, N_bytes, (u8 *)&S, simd);

	// Use the saved partial hash state.
    hctr2_hash_message(ctx, &polystate2, V, N_bytes,
				simd);
	polyval_emit(&polystate2, (u8 *)&digest, simd);

	xor(U, &UU, digest, BLOCKCIPHER_BLOCK_SIZE);
}

static void hctr2_setkey_aes128_generic(struct hctr2_ctx *ctx, const u8 *key)
{
	hctr2_setkey(ctx, key, AES_KEYSIZE_128, false);
}

static void hctr2_setkey_aes128_simd(struct hctr2_ctx *ctx, const u8 *key)
{
	hctr2_setkey(ctx, key, AES_KEYSIZE_128, true);
}

static void hctr2_setkey_aes192_generic(struct hctr2_ctx *ctx, const u8 *key)
{
	hctr2_setkey(ctx, key, AES_KEYSIZE_192, false);
}

static void hctr2_setkey_aes192_simd(struct hctr2_ctx *ctx, const u8 *key)
{
	hctr2_setkey(ctx, key, AES_KEYSIZE_192, true);
}

static void hctr2_setkey_aes256_generic(struct hctr2_ctx *ctx, const u8 *key)
{
	hctr2_setkey(ctx, key, AES_KEYSIZE_256, false);
}

static void hctr2_setkey_aes256_simd(struct hctr2_ctx *ctx, const u8 *key)
{
	hctr2_setkey(ctx, key, AES_KEYSIZE_256, true);
}

static void hctr2_encrypt_generic(const struct hctr2_ctx *ctx, u8 *dst, const u8 *src,
			   size_t nbytes, const u8 *tweak)
{
	hctr2_crypt(ctx, dst, src, nbytes, tweak, ctx->default_tweak_len, true,
		    false);
}

static void hctr2_decrypt_generic(const struct hctr2_ctx *ctx, u8 *dst, const u8 *src,
			   size_t nbytes, const u8 *tweak)
{
	hctr2_crypt(ctx, dst, src, nbytes, tweak, ctx->default_tweak_len, false,
		    false);
}

static void hctr2_encrypt_simd(const struct hctr2_ctx *ctx, u8 *dst, const u8 *src,
			size_t nbytes, const u8 *tweak)
{
	hctr2_crypt(ctx, dst, src, nbytes, tweak, ctx->default_tweak_len, true,
		    true);
}

static void hctr2_decrypt_simd(const struct hctr2_ctx *ctx, u8 *dst, const u8 *src,
			size_t nbytes, const u8 *tweak)
{
	hctr2_crypt(ctx, dst, src, nbytes, tweak, ctx->default_tweak_len, false,
		    true);
}

static void test_hctr2_testvec(const struct hctr2_testvec *v, size_t key_len, bool simd)
{
	size_t len = v->plaintext.len;
	u8 ptext[len];
	u8 ctext[len];
	struct hctr2_ctx ctx;

	ASSERT(v->key.len == key_len);
	ASSERT(v->plaintext.len >= BLOCKCIPHER_BLOCK_SIZE);
	ASSERT(v->ciphertext.len == v->plaintext.len);

	hctr2_setkey(&ctx, v->key.data, key_len, simd);
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

	for (i = 0; i < hctr2_aes128_tv_count; i++) {
		test_hctr2_testvec(&hctr2_aes128_tv[i], AES_KEYSIZE_128, false);
		test_hctr2_testvec(&hctr2_aes128_tv[i], AES_KEYSIZE_128, true);
	}

	for (i = 0; i < hctr2_aes192_tv_count; i++) {
		test_hctr2_testvec(&hctr2_aes192_tv[i], AES_KEYSIZE_192, false);
		test_hctr2_testvec(&hctr2_aes192_tv[i], AES_KEYSIZE_192, true);
	}

	for (i = 0; i < hctr2_aes256_tv_count; i++) {
		test_hctr2_testvec(&hctr2_aes256_tv[i], AES_KEYSIZE_256, false);
		test_hctr2_testvec(&hctr2_aes256_tv[i], AES_KEYSIZE_256, true);
	}
}


void test_hctr2(void)
{
	test_hctr2_testvecs();
#define ALGNAME "AES-128-HCTR2"
#define KEY_BYTES AES_KEYSIZE_128
#define IV_BYTES HCTR2_DEFAULT_TWEAK_LEN
#define KEY struct hctr2_ctx
#define SETKEY hctr2_setkey_aes128_generic
#define SETKEY_SIMD hctr2_setkey_aes128_simd
#define ENCRYPT hctr2_encrypt_generic
#define DECRYPT hctr2_decrypt_generic
#define ENCRYPT_SIMD hctr2_encrypt_simd
#define DECRYPT_SIMD hctr2_decrypt_simd
#define SIMD_IMPL_NAME "simd"
#include "cipher_benchmark_template.h"

#define ALGNAME "AES-192-HCTR2"
#define KEY_BYTES AES_KEYSIZE_192
#define IV_BYTES HCTR2_DEFAULT_TWEAK_LEN
#define KEY struct hctr2_ctx
#define SETKEY hctr2_setkey_aes192_generic
#define SETKEY_SIMD hctr2_setkey_aes192_simd
#define ENCRYPT hctr2_encrypt_generic
#define DECRYPT hctr2_decrypt_generic
#define ENCRYPT_SIMD hctr2_encrypt_simd
#define DECRYPT_SIMD hctr2_decrypt_simd
#define SIMD_IMPL_NAME "simd"
#include "cipher_benchmark_template.h"

#define ALGNAME "AES-256-HCTR2"
#define KEY_BYTES AES_KEYSIZE_256
#define IV_BYTES HCTR2_DEFAULT_TWEAK_LEN
#define KEY struct hctr2_ctx
#define SETKEY hctr2_setkey_aes256_generic
#define SETKEY_SIMD hctr2_setkey_aes256_simd
#define ENCRYPT hctr2_encrypt_generic
#define DECRYPT hctr2_decrypt_generic
#define ENCRYPT_SIMD hctr2_encrypt_simd
#define DECRYPT_SIMD hctr2_decrypt_simd
#define SIMD_IMPL_NAME "simd"
#include "cipher_benchmark_template.h"
}

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
	u128 tweaklen_part[2];
};

static void hctr2_change_tweak_len_generic(struct hctr2_ctx *ctx, const size_t tweak_len)
{
	ctx->tweaklen_part[0].b = tweak_len * 8 * 2 + 3;
	ctx->tweaklen_part[0].a = 0;
	reverse_bytes((be128 *)&ctx->tweaklen_part[0]);
	gf128mul_lle((be128 *)&ctx->tweaklen_part[0],
		     (be128 *)&ctx->polyval_key.powers[NUM_PRECOMPUTE_KEYS - 1]);
	ctx->tweaklen_part[1].b = tweak_len * 8 * 2 + 2;
	ctx->tweaklen_part[1].a = 0;
	reverse_bytes((be128 *)&ctx->tweaklen_part[1]);
	gf128mul_lle((be128 *)&ctx->tweaklen_part[1],
		     (be128 *)&ctx->polyval_key.powers[NUM_PRECOMPUTE_KEYS - 1]);
}

static void hctr2_change_tweak_len_simd(struct hctr2_ctx *ctx, const size_t tweak_len)
{
	ctx->tweaklen_part[0].b = tweak_len * 8 * 2 + 3;
	ctx->tweaklen_part[0].a = 0;
	MUL(&ctx->tweaklen_part[0], &ctx->polyval_key.powers[NUM_PRECOMPUTE_KEYS - 1]);
	ctx->tweaklen_part[1].b = tweak_len * 8 * 2 + 2;
	ctx->tweaklen_part[1].a = 0;
	MUL(&ctx->tweaklen_part[1], &ctx->polyval_key.powers[NUM_PRECOMPUTE_KEYS - 1]);
}

void hctr2_change_tweak_len(struct hctr2_ctx *ctx, const size_t tweak_len, bool simd)
{
    if(simd) {
        hctr2_change_tweak_len_simd(ctx, tweak_len);
    }
    else {
        hctr2_change_tweak_len_generic(ctx, tweak_len);    
    }
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

static void hctr2_hash_hash_tweak(const struct hctr2_ctx *ctx,
			   struct polyval_state *state, const u8 *data,
			   size_t nbytes, bool mdiv, bool simd)
{
	u128 padded_final;
	memcpy(&state->state, &ctx->tweaklen_part[mdiv ? 1 : 0],
	       sizeof(state->state));
	if (nbytes % POLYVAL_BLOCK_SIZE != 0) {
		padded_final.a = 0;
		padded_final.b = 0;
		memcpy(&padded_final,
		       data
			       + POLYVAL_BLOCK_SIZE
					 * (nbytes / POLYVAL_BLOCK_SIZE),
		       nbytes % POLYVAL_BLOCK_SIZE);
	}
	if (simd) {
		POLYVAL(data, &ctx->polyval_key, nbytes, &padded_final, &state->state);
	} else {
		polyval_generic(data, &ctx->polyval_key, nbytes, (u8 *)&padded_final,
				   (be128 *)&state->state);
	}
}

static void hctr2_hash_hash_message(const struct hctr2_ctx *ctx,
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
	if (simd) {
		POLYVAL(data, &ctx->polyval_key, nbytes, &padded_final, &state->state);
	} else {
		polyval_generic(data, &ctx->polyval_key, nbytes, (u8 *)&padded_final,
				   (be128 *)&state->state);
	}
}

static void hctr2_hash_emit(const struct hctr2_ctx *ctx,
		     struct polyval_state *state, u8 *out, bool simd) {
    memcpy(out, &state->state, POLYVAL_BLOCK_SIZE);
    if (!simd) {
        reverse_bytes((be128 *)out);
    }
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


	hctr2_hash_hash_tweak(ctx, &polystate1, tweak,
			      tweak_len, N_bytes % POLYVAL_BLOCK_SIZE == 0,
			      simd);
	memcpy(&polystate2, &polystate1, sizeof(polystate1));
	hctr2_hash_hash_message(ctx, &polystate1, N, N_bytes,
				simd);
	hctr2_hash_emit(ctx, &polystate1, (u8 *)&digest, simd);

	xor(&MM, M, digest, BLOCKCIPHER_BLOCK_SIZE);

	if (encrypt) {
		aes_encrypt(&ctx->aes_ctx, (u8 *)&UU, MM, simd);
	} else {
		aes_decrypt(&ctx->aes_ctx, (u8 *)&UU, MM, simd);
	}

	xor(&S, &MM, &UU, BLOCKCIPHER_BLOCK_SIZE);
	xor(&S, &ctx->L, &S, BLOCKCIPHER_BLOCK_SIZE);

	xctr_crypt(&ctx->aes_ctx, V, N, N_bytes, (u8 *)&S, simd);

	hctr2_hash_hash_message(ctx, &polystate2, V, N_bytes,
				simd);
	hctr2_hash_emit(ctx, &polystate2, (u8 *)&digest, simd);

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

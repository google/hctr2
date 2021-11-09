/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Common values for AES algorithms
 */
#pragma once

#include "util.h"

#define AES_MIN_KEY_SIZE	16
#define AES_MAX_KEY_SIZE	32
#define AES_KEYSIZE_128		16
#define AES_KEYSIZE_192		24
#define AES_KEYSIZE_256		32
#define AES_BLOCK_SIZE		16
#define AES_MAX_KEYLENGTH	(15 * 16)
#define AES_MAX_KEYLENGTH_U32	(AES_MAX_KEYLENGTH / sizeof(u32))

/*
 * Please ensure that the first two fields are 16-byte aligned
 * relative to the start of the structure, i.e., don't move them!
 */
struct crypto_aes_ctx {
	u32 key_enc[AES_MAX_KEYLENGTH_U32];
	u32 key_dec[AES_MAX_KEYLENGTH_U32];
	u32 key_length;
};

#ifdef __x86_64__
asmlinkage int aesni_set_key(struct crypto_aes_ctx *ctx, const u8 *in_key,
            unsigned int key_len);

asmlinkage void aesni_ecb_enc(const struct crypto_aes_ctx *ctx, u8 *dst, const u8 *src,
            size_t len);

asmlinkage void aesni_ecb_dec(const struct crypto_aes_ctx *ctx, u8 *dst, const u8 *src,
            size_t len);
#endif

#ifdef __aarch64__
asmlinkage void ce_aes_ecb_encrypt(u8 out[], u8 const in[], u8 const rk[], int rounds,
			int blocks);
asmlinkage void ce_aes_ecb_decrypt(u8 out[], u8 const in[], u8 const rk[], int rounds,
			int blocks);
#endif

int aesti_expand_key(struct crypto_aes_ctx *ctx, const u8 *in_key,
		     unsigned int key_len);

int aesti_set_key(struct crypto_aes_ctx *ctx, const u8 *in_key,
		  unsigned int key_len);
void aesti_encrypt(const struct crypto_aes_ctx *ctx, u8 *out, const u8 *in);
void aesti_decrypt(const struct crypto_aes_ctx *ctx, u8 *out, const u8 *in);

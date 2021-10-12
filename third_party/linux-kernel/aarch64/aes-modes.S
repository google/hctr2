/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * linux/arch/arm64/crypto/aes-modes.S - chaining mode wrappers for AES
 *
 * Copyright (C) 2013 - 2017 Linaro Ltd <ard.biesheuvel@linaro.org>
 */

/* included by aes-ce.S and aes-neon.S */

	.text
	.align		4

#ifndef MAX_STRIDE
#define MAX_STRIDE	4
#endif

#if MAX_STRIDE == 4
#define ST4(x...) x
#define ST5(x...)
#else
#define ST4(x...)
#define ST5(x...) x
#endif

ENTRY(aes_encrypt_block4x)
	encrypt_block4x	v0, v1, v2, v3, w3, x2, x8, w7
	ret
ENDPROC(aes_encrypt_block4x)

ENTRY(aes_decrypt_block4x)
	decrypt_block4x	v0, v1, v2, v3, w3, x2, x8, w7
	ret
ENDPROC(aes_decrypt_block4x)

#if MAX_STRIDE == 5
ENTRY(aes_encrypt_block5x)
	encrypt_block5x	v0, v1, v2, v3, v4, w3, x2, x8, w7
	ret
ENDPROC(aes_encrypt_block5x)

ENTRY(aes_decrypt_block5x)
	decrypt_block5x	v0, v1, v2, v3, v4, w3, x2, x8, w7
	ret
ENDPROC(aes_decrypt_block5x)
#endif

	/*
	 * aes_ecb_encrypt(u8 out[], u8 const in[], u8 const rk[], int rounds,
	 *		   int blocks)
	 * aes_ecb_decrypt(u8 out[], u8 const in[], u8 const rk[], int rounds,
	 *		   int blocks)
	 */

AES_FUNC_START(aes_ecb_encrypt)
	stp		x29, x30, [sp, #-16]!
	mov		x29, sp

	enc_prepare	w3, x2, x5

.LecbencloopNx:
	subs		w4, w4, #MAX_STRIDE
	bmi		.Lecbenc1x
	ld1		{v0.16b-v3.16b}, [x1], #64	/* get 4 pt blocks */
ST4(	bl		aes_encrypt_block4x		)
ST5(	ld1		{v4.16b}, [x1], #16		)
ST5(	bl		aes_encrypt_block5x		)
	st1		{v0.16b-v3.16b}, [x0], #64
ST5(	st1		{v4.16b}, [x0], #16		)
	b		.LecbencloopNx
.Lecbenc1x:
	adds		w4, w4, #MAX_STRIDE
	beq		.Lecbencout
.Lecbencloop:
	ld1		{v0.16b}, [x1], #16		/* get next pt block */
	encrypt_block	v0, w3, x2, x5, w6
	st1		{v0.16b}, [x0], #16
	subs		w4, w4, #1
	bne		.Lecbencloop
.Lecbencout:
	ldp		x29, x30, [sp], #16
	ret
AES_FUNC_END(aes_ecb_encrypt)


AES_FUNC_START(aes_ecb_decrypt)
	stp		x29, x30, [sp, #-16]!
	mov		x29, sp

	dec_prepare	w3, x2, x5

.LecbdecloopNx:
	subs		w4, w4, #MAX_STRIDE
	bmi		.Lecbdec1x
	ld1		{v0.16b-v3.16b}, [x1], #64	/* get 4 ct blocks */
ST4(	bl		aes_decrypt_block4x		)
ST5(	ld1		{v4.16b}, [x1], #16		)
ST5(	bl		aes_decrypt_block5x		)
	st1		{v0.16b-v3.16b}, [x0], #64
ST5(	st1		{v4.16b}, [x0], #16		)
	b		.LecbdecloopNx
.Lecbdec1x:
	adds		w4, w4, #MAX_STRIDE
	beq		.Lecbdecout
.Lecbdecloop:
	ld1		{v0.16b}, [x1], #16		/* get next ct block */
	decrypt_block	v0, w3, x2, x5, w6
	st1		{v0.16b}, [x0], #16
	subs		w4, w4, #1
	bne		.Lecbdecloop
.Lecbdecout:
	ldp		x29, x30, [sp], #16
	ret
AES_FUNC_END(aes_ecb_decrypt)


	.align		6
.Lcts_permute_table:
	.byte		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	.byte		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	.byte		 0x0,  0x1,  0x2,  0x3,  0x4,  0x5,  0x6,  0x7
	.byte		 0x8,  0x9,  0xa,  0xb,  0xc,  0xd,  0xe,  0xf
	.byte		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	.byte		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	
    /*
	 * aes_hctr_ctr_encrypt(u8 out[], u8 const in[], u8 const rk[], int rounds,
	 *		   int bytes, u8 ctr[])
	 */

AES_FUNC_START(aes_hctr_ctr_encrypt)
	stp		x29, x30, [sp, #-16]!
	mov		x29, sp

	enc_prepare	w3, x2, x12
	ld1		{vctr.16b}, [x5]

	umov		x12, vctr.d[0]		/* keep ctr in reg */
	movz	x11, #1

.LhctrctrloopNx:
	add		w7, w4, #15
	sub		w4, w4, #MAX_STRIDE << 4
	lsr		w7, w7, #4
	mov		w8, #MAX_STRIDE
	cmp		w7, w8
	csel		w7, w7, w8, lt

	mov		v0.16b, vctr.16b
	mov		v1.16b, vctr.16b
	mov		v2.16b, vctr.16b
	mov		v3.16b, vctr.16b
ST5(	mov		v4.16b, vctr.16b		)

	eor		x7, x12, x11
	ins		v0.d[0], x7
	add		x7, x11, #1
	add		x8, x11, #2
    eor		x7, x7, x12
	add		x9, x11, #3
	mov		v1.d[0], x7
	eor		x8, x8, x12
	eor		x9, x9, x12
ST5(	add		x10, x11, #4	)
	mov		v2.d[0], x8
	eor		x10, x10, x12
	mov		v3.d[0], x9
ST5(	mov		v4.d[0], x10			)
	tbnz		w4, #31, .Lhctrctrtail
	ld1		{v5.16b-v7.16b}, [x1], #48
ST4(	bl		aes_encrypt_block4x		)
ST5(	bl		aes_encrypt_block5x		)
	eor		v0.16b, v5.16b, v0.16b
ST4(	ld1		{v5.16b}, [x1], #16		)
	eor		v1.16b, v6.16b, v1.16b
ST5(	ld1		{v5.16b-v6.16b}, [x1], #32	)
	eor		v2.16b, v7.16b, v2.16b
	eor		v3.16b, v5.16b, v3.16b
ST5(	eor		v4.16b, v6.16b, v4.16b		)
	st1		{v0.16b-v3.16b}, [x0], #64
ST5(	st1		{v4.16b}, [x0], #16		)
ST4(add		x11, x11, #4)
ST5(add		x11, x11, #5)
	cbz		w4, .Lhctrctrout
	b		.LhctrctrloopNx

.Lhctrctrout:
	ldp		x29, x30, [sp], #16
	ret

.Lhctrctrtail:
	/* XOR up to MAX_STRIDE * 16 - 1 bytes of in/output with v0 ... v3/v4 */
	mov		x17, #16
	ands		x13, x4, #0xf
	csel		x13, x13, x17, ne

ST5(	cmp		w4, #64 - (MAX_STRIDE << 4)	)
ST5(	csel		x14, x17, xzr, gt		)
	cmp		w4, #48 - (MAX_STRIDE << 4)
	csel		x15, x17, xzr, gt
	cmp		w4, #32 - (MAX_STRIDE << 4)
	csel		x16, x17, xzr, gt
	cmp		w4, #16 - (MAX_STRIDE << 4)
	csel		x17, x17, xzr, gt
	cmp		w4, #16 - (MAX_STRIDE << 4)
	blt		.Lhctrctrout

	adr		x12, .Lcts_permute_table
	add		x12, x12, x13

ST5(	ld1		{v5.16b}, [x1], x17		)
	ld1		{v6.16b}, [x1], x16
	ld1		{v7.16b}, [x1], x15

ST4(	bl		aes_encrypt_block4x		)
ST5(	bl		aes_encrypt_block5x		)

	ld1		{v8.16b}, [x1], x14
	ld1		{v9.16b}, [x1]
	ld1		{v10.16b}, [x12]

ST4(	eor		v6.16b, v6.16b, v0.16b		)
ST4(	eor		v7.16b, v7.16b, v1.16b		)
ST4(	tbl		v3.16b, {v3.16b}, v10.16b	)
ST4(	eor		v8.16b, v8.16b, v2.16b		)
ST4(	eor		v9.16b, v9.16b, v3.16b		)

ST5(	eor		v5.16b, v5.16b, v0.16b		)
ST5(	eor		v6.16b, v6.16b, v1.16b		)
ST5(	tbl		v4.16b, {v4.16b}, v10.16b	)
ST5(	eor		v7.16b, v7.16b, v2.16b		)
ST5(	eor		v8.16b, v8.16b, v3.16b		)
ST5(	eor		v9.16b, v9.16b, v4.16b		)

		add		x16, x16, x17
		add		x15, x15, x16
ST5(		add		x14, x14, x15	)

    add		x17, x17, x0
    add		x16, x16, x0
    add		x15, x15, x0
ST5(    add		x14, x14, x0	)

ST5(	st1		{v9.16b}, [x14])
ST5(	st1		{v8.16b}, [x15])
ST5(	st1		{v7.16b}, [x16])
ST5(	st1		{v6.16b}, [x17])
ST5(	st1		{v5.16b}, [x0])

ST4(	st1		{v9.16b}, [x15])
ST4(	st1		{v8.16b}, [x16])
ST4(	st1		{v7.16b}, [x17])
ST4(	st1		{v6.16b}, [x0])
	b		.Lhctrctrout
AES_FUNC_END(aes_hctr_ctr_encrypt)


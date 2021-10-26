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
	 * aes_xctr_encrypt(u8 out[], u8 const in[], u8 const rk[], int rounds,
	 *		   int bytes, u8 const ctr[], u8 finalbuf[])
	 */

AES_FUNC_START(aes_xctr_encrypt)
	stp		x29, x30, [sp, #-16]!
	mov		x29, sp

	enc_prepare	w3, x2, x12
	ld1		{vctr.16b}, [x5]

	umov		x12, vctr.d[0]		/* keep ctr in reg */
	movz	x11, #1

.LxctrloopNx:
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
	tbnz		w4, #31, .Lxctrtail
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
	cbz		w4, .Lxctrout
	b		.LxctrloopNx

.Lxctrout:
	ldp		x29, x30, [sp], #16
	ret

.Lxctrtail:
	/* XOR up to MAX_STRIDE * 16 - 1 bytes of in/output with v0 ... v3/v4 */
	mov		x17, #16
	ands		x13, x4, #0xf
	csel		x13, x13, x17, ne

ST5(	cmp		w4, #64 - (MAX_STRIDE << 4))
ST5(	csel		x14, x17, xzr, gt		)
ST5(	csel		x10, x10, x9, gt		)
	cmp		w4, #48 - (MAX_STRIDE << 4)
	csel		x15, x17, xzr, gt
ST5(	csel		x10, x10, x8, gt		)
	cmp		w4, #32 - (MAX_STRIDE << 4)
	csel		x16, x17, xzr, gt
ST5(	csel		x10, x10, x7, gt		)
	cmp		w4, #16 - (MAX_STRIDE << 4)
	ble		.Lxctrtail1x

ST5(	mov		v4.d[0], x10			)

	adr		x12, .Lcts_permute_table
	add		x12, x12, x13

ST5(	ld1		{v5.16b}, [x1], x16		)
	ld1		{v6.16b}, [x1], x15
	ld1		{v7.16b}, [x1], x14

ST4(	bl		aes_encrypt_block4x		)
ST5(	bl		aes_encrypt_block5x		)

	ld1		{v8.16b}, [x1], x13
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

	add		x15, x15, x16
ST5(	add		x14, x14, x15			)
ST5(	add		x13, x13, x14			)
ST4(	add		x13, x13, x15			)

	add		x16, x16, x0
	add		x15, x15, x0
ST5(	add		x14, x14, x0			)
	add		x13, x13, x0

ST5(	st1		{v9.16b}, [x13])
ST5(	st1		{v8.16b}, [x14])
ST5(	st1		{v7.16b}, [x15])
ST5(	st1		{v6.16b}, [x16])
ST5(	st1		{v5.16b}, [x0])

ST4(	st1		{v9.16b}, [x15])
ST4(	st1		{v8.16b}, [x16])
ST4(	st1		{v7.16b}, [x17])
ST4(	st1		{v6.16b}, [x0])
	b		.Lxctrout

.Lxctrtail1x:
	csel		x0, x0, x6, eq		// use finalbuf if less than a full block
	csel		x1, x1, x6, eq		// use finalbuf if less than a full block
	ld1		{v5.16b}, [x1]
ST5(	mov		v3.16b, v0.16b			)
	encrypt_block	v3, w3, x2, x8, w7
	eor		v5.16b, v5.16b, v3.16b
	st1		{v5.16b}, [x0]
	b		.Lxctrout
AES_FUNC_END(aes_xctr_encrypt)


	/*
	 * aes_xts_encrypt(u8 out[], u8 const in[], u8 const rk1[], int rounds,
	 *		   int bytes, u8 const rk2[], u8 iv[], int first)
	 * aes_xts_decrypt(u8 out[], u8 const in[], u8 const rk1[], int rounds,
	 *		   int bytes, u8 const rk2[], u8 iv[], int first)
	 */

	.macro		next_tweak, out, in, tmp
	sshr		\tmp\().2d,  \in\().2d,   #63
	and		\tmp\().16b, \tmp\().16b, xtsmask.16b
	add		\out\().2d,  \in\().2d,   \in\().2d
	ext		\tmp\().16b, \tmp\().16b, \tmp\().16b, #8
	eor		\out\().16b, \out\().16b, \tmp\().16b
	.endm

	.macro		xts_load_mask, tmp
	movi		xtsmask.2s, #0x1
	movi		\tmp\().2s, #0x87
	uzp1		xtsmask.4s, xtsmask.4s, \tmp\().4s
	.endm

AES_FUNC_START(aes_xts_encrypt)
	stp		x29, x30, [sp, #-16]!
	mov		x29, sp

	ld1		{v4.16b}, [x6]
	xts_load_mask	v8
	cbz		w7, .Lxtsencnotfirst

	enc_prepare	w3, x5, x8
	xts_cts_skip_tw	w7, .LxtsencNx
	encrypt_block	v4, w3, x5, x8, w7		/* first tweak */
	enc_switch_key	w3, x2, x8
	b		.LxtsencNx

.Lxtsencnotfirst:
	enc_prepare	w3, x2, x8
.LxtsencloopNx:
	next_tweak	v4, v4, v8
.LxtsencNx:
	subs		w4, w4, #64
	bmi		.Lxtsenc1x
	ld1		{v0.16b-v3.16b}, [x1], #64	/* get 4 pt blocks */
	next_tweak	v5, v4, v8
	eor		v0.16b, v0.16b, v4.16b
	next_tweak	v6, v5, v8
	eor		v1.16b, v1.16b, v5.16b
	eor		v2.16b, v2.16b, v6.16b
	next_tweak	v7, v6, v8
	eor		v3.16b, v3.16b, v7.16b
	bl		aes_encrypt_block4x
	eor		v3.16b, v3.16b, v7.16b
	eor		v0.16b, v0.16b, v4.16b
	eor		v1.16b, v1.16b, v5.16b
	eor		v2.16b, v2.16b, v6.16b
	st1		{v0.16b-v3.16b}, [x0], #64
	mov		v4.16b, v7.16b
	cbz		w4, .Lxtsencret
	xts_reload_mask	v8
	b		.LxtsencloopNx
.Lxtsenc1x:
	adds		w4, w4, #64
	beq		.Lxtsencout
	subs		w4, w4, #16
	bmi		.LxtsencctsNx
.Lxtsencloop:
	ld1		{v0.16b}, [x1], #16
.Lxtsencctsout:
	eor		v0.16b, v0.16b, v4.16b
	encrypt_block	v0, w3, x2, x8, w7
	eor		v0.16b, v0.16b, v4.16b
	cbz		w4, .Lxtsencout
	subs		w4, w4, #16
	next_tweak	v4, v4, v8
	bmi		.Lxtsenccts
	st1		{v0.16b}, [x0], #16
	b		.Lxtsencloop
.Lxtsencout:
	st1		{v0.16b}, [x0]
.Lxtsencret:
	st1		{v4.16b}, [x6]
	ldp		x29, x30, [sp], #16
	ret

.LxtsencctsNx:
	mov		v0.16b, v3.16b
	sub		x0, x0, #16
.Lxtsenccts:
	adr		x8, .Lcts_permute_table

	add		x1, x1, w4, sxtw	/* rewind input pointer */
	add		w4, w4, #16		/* # bytes in final block */
	add		x9, x8, #32
	add		x8, x8, x4
	sub		x9, x9, x4
	add		x4, x0, x4		/* output address of final block */

	ld1		{v1.16b}, [x1]		/* load final block */
	ld1		{v2.16b}, [x8]
	ld1		{v3.16b}, [x9]

	tbl		v2.16b, {v0.16b}, v2.16b
	tbx		v0.16b, {v1.16b}, v3.16b
	st1		{v2.16b}, [x4]			/* overlapping stores */
	mov		w4, wzr
	b		.Lxtsencctsout
AES_FUNC_END(aes_xts_encrypt)

AES_FUNC_START(aes_xts_decrypt)
	stp		x29, x30, [sp, #-16]!
	mov		x29, sp

	/* subtract 16 bytes if we are doing CTS */
	sub		w8, w4, #0x10
	tst		w4, #0xf
	csel		w4, w4, w8, eq

	ld1		{v4.16b}, [x6]
	xts_load_mask	v8
	xts_cts_skip_tw	w7, .Lxtsdecskiptw
	cbz		w7, .Lxtsdecnotfirst

	enc_prepare	w3, x5, x8
	encrypt_block	v4, w3, x5, x8, w7		/* first tweak */
.Lxtsdecskiptw:
	dec_prepare	w3, x2, x8
	b		.LxtsdecNx

.Lxtsdecnotfirst:
	dec_prepare	w3, x2, x8
.LxtsdecloopNx:
	next_tweak	v4, v4, v8
.LxtsdecNx:
	subs		w4, w4, #64
	bmi		.Lxtsdec1x
	ld1		{v0.16b-v3.16b}, [x1], #64	/* get 4 ct blocks */
	next_tweak	v5, v4, v8
	eor		v0.16b, v0.16b, v4.16b
	next_tweak	v6, v5, v8
	eor		v1.16b, v1.16b, v5.16b
	eor		v2.16b, v2.16b, v6.16b
	next_tweak	v7, v6, v8
	eor		v3.16b, v3.16b, v7.16b
	bl		aes_decrypt_block4x
	eor		v3.16b, v3.16b, v7.16b
	eor		v0.16b, v0.16b, v4.16b
	eor		v1.16b, v1.16b, v5.16b
	eor		v2.16b, v2.16b, v6.16b
	st1		{v0.16b-v3.16b}, [x0], #64
	mov		v4.16b, v7.16b
	cbz		w4, .Lxtsdecout
	xts_reload_mask	v8
	b		.LxtsdecloopNx
.Lxtsdec1x:
	adds		w4, w4, #64
	beq		.Lxtsdecout
	subs		w4, w4, #16
.Lxtsdecloop:
	ld1		{v0.16b}, [x1], #16
	bmi		.Lxtsdeccts
.Lxtsdecctsout:
	eor		v0.16b, v0.16b, v4.16b
	decrypt_block	v0, w3, x2, x8, w7
	eor		v0.16b, v0.16b, v4.16b
	st1		{v0.16b}, [x0], #16
	cbz		w4, .Lxtsdecout
	subs		w4, w4, #16
	next_tweak	v4, v4, v8
	b		.Lxtsdecloop
.Lxtsdecout:
	st1		{v4.16b}, [x6]
	ldp		x29, x30, [sp], #16
	ret

.Lxtsdeccts:
	adr		x8, .Lcts_permute_table

	add		x1, x1, w4, sxtw	/* rewind input pointer */
	add		w4, w4, #16		/* # bytes in final block */
	add		x9, x8, #32
	add		x8, x8, x4
	sub		x9, x9, x4
	add		x4, x0, x4		/* output address of final block */

	next_tweak	v5, v4, v8

	ld1		{v1.16b}, [x1]		/* load final block */
	ld1		{v2.16b}, [x8]
	ld1		{v3.16b}, [x9]

	eor		v0.16b, v0.16b, v5.16b
	decrypt_block	v0, w3, x2, x8, w7
	eor		v0.16b, v0.16b, v5.16b

	tbl		v2.16b, {v0.16b}, v2.16b
	tbx		v0.16b, {v1.16b}, v3.16b

	st1		{v2.16b}, [x4]			/* overlapping stores */
	mov		w4, wzr
	b		.Lxtsdecctsout
AES_FUNC_END(aes_xts_decrypt)

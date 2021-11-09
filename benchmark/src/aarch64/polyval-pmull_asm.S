/*
 * Copyright 2021 Google LLC
 *
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 */
#include "asm_common.h"
#include "../polyval-asm.h"

BLOCKS_LEFT	.req	x2
OP1	.req	x9
KEY_START	.req	x10
EXTRA_BYTES	.req	x11
IDX	.req	x12
TMP	.req	x13
PARTIAL_LEFT	.req	x14

M0	.req	v0
M1	.req	v1
M2	.req	v2
M3	.req	v3
M4	.req	v4
M5	.req	v5
M6	.req	v6
M7	.req	v7
KEY8	.req	v8
KEY7	.req	v9
KEY6	.req	v10
KEY5	.req	v11
KEY4	.req	v12
KEY3	.req	v13
KEY2	.req	v14
KEY1	.req	v15
PL	.req	v16
PH	.req	v17
T	.req	v18
Z	.req	v19
C	.req	v20
D	.req	v21
E	.req	v22
SUM	.req	v23
GSTAR	.req	v24

	.text
	.align	4

	.arch	armv8-a+crypto
	.align	4

.Lgstar:
	.quad	0xc200000000000000, 0xc200000000000000

/*
 * Computes the first step of Karatsuba multiplication of
 * registers X, Y.
 *
 * Updates C, D, E
 * Clobbers v25, v26, X, Y
 */
.macro karatsuba1 X Y
	X .req \X
	Y .req \Y
	ext	v25.16b, X.16b, Y.16b, #8
	eor	v25.16b, v25.16b, X.16b
	ext	v26.16b, Y.16b, Y.16b, #8
	eor	v26.16b, v26.16b, Y.16b
	pmull	v26.1q, v25.1d, v26.1d
	pmull2	v25.1q, X.2d, Y.2d
	pmull	X.1q, X.1d, Y.1d
	eor	E.16b, E.16b, v26.16b
	eor	C.16b, C.16b, v25.16b
	eor	D.16b, D.16b, X.16b
	.unreq X
	.unreq Y
.endm

/*
 * Computes the 256-bit polynomial represented by C, D, E.
 * Stores this polynomial in PH, PL.
 *
 * Sets PH, PL
 * Clobbers C, D, E, v4
 */
.macro karatsuba2
	ext	v4.16b, D.16b, C.16b, #8
	eor	E.16b, E.16b, v4.16b //[E1 ^ C0 : E0 ^ D1]
	eor	v4.16b, C.16b, D.16b //[C1 ^ D1 : C0 ^ D0]
	eor	v4.16b, E.16b, v4.16b //[C0 ^ C1 ^ D1 ^ E1 : D1 ^ C0 ^ D0 ^ E0]
	ext	C.16b, C.16b, C.16b, #8 // [C0 : C1]
	ext	D.16b, D.16b, D.16b, #8 // [D0 : D1]
	ext	PH.16b, v4.16b, C.16b, #8 //[C1 : C1 ^ D1 ^ E1 ^ C0]
	ext	PL.16b, D.16b, v4.16b, #8 //[D1 ^ C0 ^ D0 ^ E0 : D0]
.endm

/*
 * Perform montgomery reduction of the polynomial
 * represented by PH, PL. Stores the reduced polynomial
 * in PH.
 *
 * Sets PH
 * Clobbers T, Z, PL
 */
.macro montgomery_reduction
	pmull	T.1q, GSTAR.1d, PL.1d
	ext	T.16b, T.16b, T.16b, #8
	eor	PL.16b, PL.16b, T.16b
	pmull2	Z.1q, GSTAR.2d, PL.2d
	eor	Z.16b, PL.16b, Z.16b
	eor	PH.16b, PH.16b, Z.16b
.endm

/*
 * Compute Polyval on 8 blocks.
 *
 * If reduce is set, performs interleaved montgomery reduction
 * on the last full_stride iteration's PL, PH.
 *
 * Sets PL, PH.
 */
.macro full_stride reduce
	.set reduce, \reduce
	eor		C.16b, C.16b, C.16b
	eor		D.16b, D.16b, D.16b
	eor		E.16b, E.16b, E.16b
	
	ld1		{M0.16b, M1.16b, M2.16b, M3.16b}, [x0], #64
	ld1		{M4.16b, M5.16b, M6.16b, M7.16b}, [x0], #64

	karatsuba1 M7 KEY1
	.if(reduce)
	pmull	T.1q, GSTAR.1d, PL.1d
	.endif

	karatsuba1 M6 KEY2
	.if(reduce)
	ext	T.16b, T.16b, T.16b, #8
	.endif

	karatsuba1 M5 KEY3
	.if(reduce)
	eor	PL.16b, PL.16b, T.16b
	.endif

	karatsuba1 M4 KEY4
	.if(reduce)
	pmull2	Z.1q, GSTAR.2d, PL.2d
	.endif

	karatsuba1 M3 KEY5
	.if(reduce)
	eor	Z.16b, PL.16b, Z.16b
	.endif

	karatsuba1 M2 KEY6
	.if(reduce)
	eor	PH.16b, PH.16b, Z.16b
	.endif

	karatsuba1 M1 KEY7
	.if(reduce)
	mov	SUM.16b, PH.16b
	.endif
	eor	M0.16b, M0.16b, SUM.16b

	karatsuba1 M0 KEY8

	karatsuba2
.endm

/*
 * Handle any extra blocks before
 * full_stride loop.
 */
.macro partial_stride
	eor		C.16b, C.16b, C.16b
	eor		D.16b, D.16b, D.16b
	eor		E.16b, E.16b, E.16b
	add		KEY_START, x1, #(NUM_PRECOMPUTE_KEYS << 4)
	sub		KEY_START, KEY_START, PARTIAL_LEFT, lsl #4
	ld1		{v0.16b}, [KEY_START]
	mov		v1.16b, SUM.16b
	karatsuba1 v0 v1
	karatsuba2
	montgomery_reduction
	mov		SUM.16b, PH.16b
	eor		C.16b, C.16b, C.16b
	eor		D.16b, D.16b, D.16b
	eor		E.16b, E.16b, E.16b
	mov		IDX, XZR
.LloopPartial:
	cmp		IDX, PARTIAL_LEFT
	bge		.LloopExitPartial

	sub		TMP, IDX, PARTIAL_LEFT

	cmp		TMP, #-4
	bgt		.Lgt4Partial
	ld1		{M0.16b, M1.16b,  M2.16b, M3.16b}, [x0], #64
	// Clobber key registers
	ld1		{KEY8.16b, KEY7.16b, KEY6.16b,  KEY5.16b}, [KEY_START], #64
	karatsuba1 M0 KEY8
	karatsuba1 M1 KEY7
	karatsuba1 M2 KEY6
	karatsuba1 M3 KEY5
	add		IDX, IDX, #4
	b		.LoutPartial

.Lgt4Partial:
	cmp		TMP, #-3
	bgt		.Lgt3Partial
	ld1		{M0.16b, M1.16b, M2.16b}, [x0], #48
	// Clobber key registers
	ld1		{KEY8.16b, KEY7.16b, KEY6.16b}, [KEY_START], #48
	karatsuba1 M0 KEY8
	karatsuba1 M1 KEY7
	karatsuba1 M2 KEY6
	add		IDX, IDX, #3
	b		.LoutPartial

.Lgt3Partial:
	cmp		TMP, #-2
	bgt		.Lgt2Partial
	ld1		{M0.16b, M1.16b}, [x0], #32
	// Clobber key registers
	ld1		{KEY8.16b, KEY7.16b}, [KEY_START], #32
	karatsuba1 M0 KEY8
	karatsuba1 M1 KEY7
	add		IDX, IDX, #2
	b		.LoutPartial

.Lgt2Partial:
	ld1		{M0.16b}, [x0], #16
	// Clobber key registers
	ld1		{KEY8.16b}, [KEY_START], #16
	karatsuba1 M0 KEY8
	add		IDX, IDX, #1
.LoutPartial:
	b .LloopPartial
.LloopExitPartial:
	karatsuba2
	montgomery_reduction
	eor		SUM.16b, SUM.16b, PH.16b
.endm

/*
 * Perform montgomery multiplication in GF128 and store result in op1.
 *
 * Computes op1*op2*x^{-128} mod x^128 + x^127 + x^126 + x^121 + 1
 * If op1, op2 are in montgomery form,  this computes the montgomery
 * form of op1*op2.
 *
 * void pmull_polyval_mul(ble128* op1, const ble128* op2);
 */
ENTRY(pmull_polyval_mul)
	adr		TMP, .Lgstar
	ld1		{GSTAR.2d}, [TMP]
	eor		C.16b, C.16b, C.16b
	eor		D.16b, D.16b, D.16b
	eor		E.16b, E.16b, E.16b
	ld1		{v0.16b}, [x0]
	ld1		{v1.16b}, [x1]
	karatsuba1 v0 v1
	karatsuba2
	montgomery_reduction
	st1		{PH.16b}, [x0]
	ret
ENDPROC(pmull_polyval_mul)

/*
 * Perform polynomial evaluation as specified by POLYVAL. Multiplies the value stored
 * at accumulator by h^n and XORs the evaluated polynomial into it.
 *
 * Computes h^k*accumulator + h^kM_0 + ... + h^1M_{k-1} (No constant term)
 *
 * x0 (OP1) - pointer to message blocks
 * x1 - pointer to precomputed key struct
 * x2 - number of blocks to hash
 * x3 - location to XOR with evaluated polynomial
 *
 * void pmull_polyval_update(const u8 *in, const struct polyhash_key* keys, uint64_t nblocks, ble128* accumulator);
 */
ENTRY(pmull_polyval_update)
	adr		TMP, .Lgstar
	ld1		{GSTAR.2d}, [TMP]
	ld1		{SUM.16b}, [x3]
	ands		PARTIAL_LEFT, BLOCKS_LEFT, #7
	beq		.LskipPartial
	partial_stride
.LskipPartial:
	subs		BLOCKS_LEFT, BLOCKS_LEFT, #NUM_PRECOMPUTE_KEYS
	blt		.LstrideLoopExit
	ld1		{KEY8.16b, KEY7.16b, KEY6.16b, KEY5.16b}, [x1], #64
	ld1		{KEY4.16b, KEY3.16b, KEY2.16b, KEY1.16b}, [x1], #64
	full_stride 0
	subs		BLOCKS_LEFT, BLOCKS_LEFT, #NUM_PRECOMPUTE_KEYS
	blt		.LstrideLoopExitReduce
.LstrideLoop:
	full_stride 1
	subs		BLOCKS_LEFT, BLOCKS_LEFT, #NUM_PRECOMPUTE_KEYS
	bge		.LstrideLoop
.LstrideLoopExitReduce:
	montgomery_reduction
	mov		SUM.16b, PH.16b
.LstrideLoopExit:
	st1		{SUM.16b}, [x3]
	ret
ENDPROC(pmull_polyval_update)

/*
 * Copyright 2021 Google LLC
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 */
#include "asm_common.h"
#include "../polyval-asm.h"

BLOCKS_LEFT	.req	x2 // Ensure caller saved, maybe switch
OP1			.req	x9 // Ensure caller saved, maybe switch
KEY_START			.req	x10 // Ensure caller saved, maybe switch
EXTRA_BYTES	.req	x11 // Ensure caller saved, maybe switch
IDX			.req	x12 // Ensure caller saved, maybe switch
TMP			.req	x13 // Ensure caller saved, maybe switch

M0			.req	v0
M1			.req	v1
M2			.req	v2
M3			.req	v3
M4			.req	v4
M5			.req	v5
M6			.req	v6
M7			.req	v7
KEY8		.req	v8
KEY7		.req	v9
KEY6		.req	v10
KEY5		.req	v11
KEY4		.req	v12
KEY3		.req	v13
KEY2		.req	v14
KEY1		.req	v15
PL			.req	v16
PH			.req	v17
T			.req	v18
Z			.req	v19
C			.req	v20
D			.req	v21
E			.req	v22
SUM			.req	v23
GSTAR		.req	v24

	.text
	.align		4

	.arch		armv8-a+crypto
	.align		4

.Lgstar:
	.quad		0xc200000000000000, 0xc200000000000000

.macro karatsuba1 X Y
	X .req \X
	Y .req \Y
	ext				v25.16b, X.16b, Y.16b, #8
	eor				v25.16b, v25.16b, X.16b
	ext				v26.16b, Y.16b, Y.16b, #8
	eor				v26.16b, v26.16b, Y.16b
	pmull			v26.1q, v25.1d, v26.1d
	pmull2			v25.1q, X.2d, Y.2d
	pmull			X.1q, X.1d, Y.1d
	eor				E.16b, E.16b, v26.16b
	eor				C.16b, C.16b, v25.16b
	eor				D.16b, D.16b, X.16b
	.unreq X
	.unreq Y
.endm

// TODO: Reduce instructions?
.macro karatsuba2
		ext				v4.16b, D.16b, C.16b, #8 // [C0 : D1] Verify this instruction?
		eor				E.16b, E.16b, v4.16b //[E1 ^ C0 : E0 ^ D1]
		eor				v4.16b, C.16b, D.16b //[C1 ^ D1 : C0 ^ D0]
		eor				v4.16b, E.16b, v4.16b //[C0 ^ C1 ^ D1 ^ E1 : D1 ^ C0 ^ D0 ^ E0]
		ext				C.16b, C.16b, C.16b, #8 // [C0 : C1] Verify this instruction?
		ext				D.16b, D.16b, D.16b, #8 // [D0 : D1] Verify this instruction?
		ext				PH.16b, v4.16b, C.16b, #8 //[C1 : C1 ^ D1 ^ E1 ^ C0]
		ext				PL.16b, D.16b, v4.16b, #8 //[D1 ^ C0 ^ D0 ^ E0 : D0]
.endm

.macro montgomery_reduction
		pmull			T.1q, GSTAR.1d, PL.1d
		ext				T.16b, T.16b, T.16b, #8
		eor				PL.16b, PL.16b, T.16b
		pmull2			Z.1q, GSTAR.2d, PL.2d
		eor				Z.16b, PL.16b, Z.16b
		eor				PH.16b, PH.16b, Z.16b
.endm

.macro full_stride
	eor					C.16b, C.16b, C.16b // Check if there's a faster zeroing method
	eor					D.16b, D.16b, D.16b // Check if there's a faster zeroing method
	eor					E.16b, E.16b, E.16b // Check if there's a faster zeroing method
	ld1					{M0.16b}, [x0], #16
	ld1					{M1.16b}, [x0], #16
	ld1					{M2.16b}, [x0], #16
	ld1					{M3.16b}, [x0], #16
	ld1					{M4.16b}, [x0], #16
	ld1					{M5.16b}, [x0], #16
	ld1					{M6.16b}, [x0], #16
	ld1					{M7.16b}, [x0], #16
	eor					M0.16b, M0.16b, SUM.16b
	karatsuba1 M0 KEY8
	karatsuba1 M1 KEY7
	karatsuba1 M2 KEY6
	karatsuba1 M3 KEY5
	karatsuba1 M4 KEY4
	karatsuba1 M5 KEY3
	karatsuba1 M6 KEY2
	karatsuba1 M7 KEY1
	karatsuba2
	montgomery_reduction
	mov					SUM.16b, PH.16b
.endm

.macro partial_stride
	eor					C.16b, C.16b, C.16b // Check if there's a faster zeroing method
	eor					D.16b, D.16b, D.16b // Check if there's a faster zeroing method
	eor					E.16b, E.16b, E.16b // Check if there's a faster zeroing method
	mov					TMP, BLOCKS_LEFT
	cmp					EXTRA_BYTES, #0
	csinc				TMP, TMP, TMP, eq
	lsl					TMP, TMP, #4
    // x1 currently points at the end of the key array
	subs				KEY_START, x1, TMP
	ld1					{v0.16b}, [KEY_START]
	mov					v1.16b, SUM.16b
	karatsuba1 v0 v1
	karatsuba2
	montgomery_reduction
	mov					SUM.16b, PH.16b
	eor					C.16b, C.16b, C.16b // Check if there's a faster zeroing method
	eor					D.16b, D.16b, D.16b // Check if there's a faster zeroing method
	eor					E.16b, E.16b, E.16b // Check if there's a faster zeroing method
	mov					IDX, XZR
.LoopPartial:
	cmp 				IDX, BLOCKS_LEFT
	bge 				.LoopExitPartial

	subs				TMP, IDX, BLOCKS_LEFT

	cmp					TMP, #-4
    bgt					.gt4Partial
	ld1					{M0.16b}, [x0], #16
	ld1					{M1.16b}, [x0], #16
	ld1					{M2.16b}, [x0], #16
	ld1					{M3.16b}, [x0], #16
    // Clobber key registers
	ld1					{KEY8.16b}, [KEY_START], #16
	ld1					{KEY7.16b}, [KEY_START], #16
	ld1					{KEY6.16b}, [KEY_START], #16
	ld1					{KEY5.16b}, [KEY_START], #16
	karatsuba1 M0 KEY8
	karatsuba1 M1 KEY7
	karatsuba1 M2 KEY6
	karatsuba1 M3 KEY5
	add					IDX, IDX, #4
	b					.outPartial

.gt4Partial:
	cmp					TMP, #-3
	bgt					.gt3Partial
	ld1					{M0.16b}, [x0], #16
	ld1					{M1.16b}, [x0], #16
	ld1					{M2.16b}, [x0], #16
    // Clobber key registers
	ld1					{KEY8.16b}, [KEY_START], #16
	ld1					{KEY7.16b}, [KEY_START], #16
	ld1					{KEY6.16b}, [KEY_START], #16
	karatsuba1 M0 KEY8
	karatsuba1 M1 KEY7
	karatsuba1 M2 KEY6
	add					IDX, IDX, #3
	b					.outPartial

.gt3Partial:
	cmp					TMP, #-2
	bgt					.gt2Partial
	ld1					{M0.16b}, [x0], #16
	ld1					{M1.16b}, [x0], #16
	// Clobber key registers
	ld1					{KEY8.16b}, [KEY_START], #16
	ld1					{KEY7.16b}, [KEY_START], #16
	karatsuba1 M0 KEY8
	karatsuba1 M1 KEY7
	add					IDX, IDX, #2
    b					.outPartial

.gt2Partial:
	ld1					{M0.16b}, [x0], #16
	// Clobber key registers
	ld1					{KEY8.16b}, [KEY_START], #16
	karatsuba1 M0 KEY8
	add					IDX, IDX, #1
.outPartial:
	b .LoopPartial
.LoopExitPartial:
	# Handle extra block
	cmp					EXTRA_BYTES, #0
	beq					.no_extra_block
	ld1					{M0.16b}, [x3]
	karatsuba1 M0 KEY1
.no_extra_block:
	karatsuba2
	montgomery_reduction
	eor					SUM.16b, SUM.16b, PH.16b
.endm

/*
 * Perform montgomery multiplication in GF128 and store result in op1.
 *
 * Computes op1*op2*x^{-128} mod x^128 + x^127 + x^126 + x^121 + 1
 *
 * void pmull_polyval_mul(u128* op1, const u128* op2);
 */
ENTRY(pmull_polyval_mul)
	adr					TMP, .Lgstar
	ld1					{GSTAR.2d}, [TMP]
	eor					C.16b, C.16b, C.16b // Check if there's a faster zeroing method
	eor					D.16b, D.16b, D.16b // Check if there's a faster zeroing method
	eor					E.16b, E.16b, E.16b // Check if there's a faster zeroing method
	ld1					{v0.16b}, [x0]
	ld1					{v1.16b}, [x1]
	karatsuba1 v0 v1
	karatsuba2
	montgomery_reduction
	st1					{PH.16b}, [x0]
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
 * x2 - number of bytes to hash
 * x3 - final block (if nbytes % 16 != 0) used to allow padding without modifying *in
 * x4 - location to XOR with evaluated polynomial
 *
 * void pmull_polyval(const u8 *in, const struct polyhash_key* keys, uint64_t nbytes, const u128* final, u128* accumulator);
 */
ENTRY(pmull_polyval)
	adr					TMP, .Lgstar
	ld1					{GSTAR.2d}, [TMP]
	mov					KEY_START, x1
	ld1					{KEY8.16b}, [x1], #16
	ld1					{KEY7.16b}, [x1], #16
	ld1					{KEY6.16b}, [x1], #16
	ld1					{KEY5.16b}, [x1], #16
	ld1					{KEY4.16b}, [x1], #16
	ld1					{KEY3.16b}, [x1], #16
	ld1					{KEY2.16b}, [x1], #16
	ld1					{KEY1.16b}, [x1], #16
	ands				EXTRA_BYTES, x2, 0xf
	lsr					BLOCKS_LEFT, BLOCKS_LEFT, #4
	ld1					{SUM.16b}, [x4]
.StrideLoop:
	cmp					BLOCKS_LEFT, #NUM_PRECOMPUTE_KEYS
	blt					.StrideLoopExit
	full_stride
	subs				BLOCKS_LEFT, BLOCKS_LEFT, #NUM_PRECOMPUTE_KEYS
	b					.StrideLoop
.StrideLoopExit:
	cmp					BLOCKS_LEFT, 0
	bne					.DoPartial
	cmp					EXTRA_BYTES, 0
	bne					.DoPartial
	b					.SkipPartial
.DoPartial:
	partial_stride
.SkipPartial:
	st1					{SUM.16b}, [x4]
	ret
ENDPROC(pmull_polyval)

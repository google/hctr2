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
OP2			.req	x10 // Ensure caller saved, maybe switch
EXTRA_BYTES	.req	x11 // Ensure caller saved, maybe switch
IDX			.req	x12 // Ensure caller saved, maybe switch
TMP			.req	x13 // Ensure caller saved, maybe switch

PL			.req	v16
PH			.req	v17
T			.req	v18
Z			.req	v19
C			.req	v20
D			.req	v21
EF			.req	v22
SUM			.req	v23
GSTAR		.req	v24

	.text
	.align		4

	.arch		armv8-a+crypto
	.align		4

.Lgstar:
	.quad		0xc200000000000000, 0xc200000000000000

var_a1	.req v0
var_a2	.req v1
var_a3	.req v2
var_a4	.req v3
.macro setregs n
	.unreq var_a1
	.unreq var_a2
	.unreq var_a3
	.unreq var_a4
	.if \n == 0
		var_a1	.req v0
		var_a2	.req v1
		var_a3	.req v2
		var_a4	.req v3
	.endif
	.if \n == 1
		var_a1	.req v4
		var_a2	.req v5
		var_a3	.req v6
		var_a4	.req v7
	.endif
	.if \n == 2
		var_a1	.req v8
		var_a2	.req v9
		var_a3	.req v10
		var_a4	.req v11
	.endif
	.if \n == 3
		var_a1	.req v12
		var_a2	.req v13
		var_a3	.req v14
		var_a4	.req v15
	.endif
.endm

.macro karatsuba1_iteration i first
	.set i, \i
	.set first, \first
	setregs i
	ld1				{var_a1.16b}, [OP1]
	ld1				{var_a2.16b}, [OP2]
	add				OP1, OP1, #16
	add				OP2, OP2, #16
	.if(i == 0 && first == 1)
		eor			var_a1.16b, var_a1.16b, SUM.16b
	.endif
	
	pmull var_a3.1q, var_a1.1d, var_a2.1d
	pmull2 var_a4.1q, var_a1.2d, var_a2.2d
	eor				C.16b, C.16b, var_a3.16b
	eor				D.16b, D.16b, var_a4.16b
	ext				var_a1.16b, var_a1.16b, var_a1.16b, #8
	pmull var_a3.1q, var_a1.1d, var_a2.1d
	pmull2 var_a4.1q, var_a1.2d, var_a2.2d
	eor				EF.16b, EF.16b, var_a3.16b
	eor				EF.16b, EF.16b, var_a4.16b
.endm

.macro karatsuba1 b first
	.set by, \b
    .set first, \first

	.set i, 0
	.rept (by)
		karatsuba1_iteration i first
		.set i, (i +1)
	.endr
.endm

/*
 * Karatsuba1 without loading
 * Expects op1 in x0 and op2 in x2
 */
.macro karatsuba1_noload
	pmull v1.1q, v0.1d, v2.1d
	pmull2 v3.1q, v0.2d, v2.2d
	eor				C.16b, C.16b, v1.16b
	eor				D.16b, D.16b, v3.16b
	ext				v0.16b, v0.16b, v0.16b, #8
	pmull v1.1q, v0.1d, v2.1d
	pmull2 v3.1q, v0.2d, v2.2d
	eor				EF.16b, EF.16b, v1.16b
	eor				EF.16b, EF.16b, v3.16b
.endm

// TODO: Reduce instructions?
.macro karatsuba2
	mov PL.d[0], xzr
	mov PH.d[1], xzr
	mov PL.d[1], EF.d[0]
	mov PH.d[0], EF.d[1]
	eor PL.16b, PL.16b, C.16b
	eor PH.16b, PH.16b, D.16b
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
	eor					EF.16b, EF.16b, EF.16b // Check if there's a faster zeroing method
	mov					OP1, x0
	mov					OP2, x1
	mov					IDX, XZR
	karatsuba1 4 1
.Loop:
	cmp 				IDX, #NUM_PRECOMPUTE_KEYS-4
	bge 				.LoopExit

	subs				TMP, IDX, #NUM_PRECOMPUTE_KEYS-4

	cmp					TMP, #-4
    bgt					.gt4
	karatsuba1 4 0
	add					IDX, IDX, #4
    b					.out

.gt4:
	cmp					TMP, #-3
	bgt					.gt3
	karatsuba1 3 0
	add					IDX, IDX, #3
    b					.out

.gt3:
	cmp					TMP, #-2
	bgt					.gt2
	karatsuba1 2 0
	add					IDX, IDX, #2
    b					.out

.gt2:
	karatsuba1 1 0
	add					IDX, IDX, #1
.out:
	b .Loop
.LoopExit:
	add					x0, x0, #(NUM_PRECOMPUTE_KEYS*16)
	karatsuba2
	montgomery_reduction
	mov					SUM.16b, PH.16b
.endm

.macro partial_stride
	eor					C.16b, C.16b, C.16b // Check if there's a faster zeroing method
	eor					D.16b, D.16b, D.16b // Check if there's a faster zeroing method
	eor					EF.16b, EF.16b, EF.16b // Check if there's a faster zeroing method
	mov					TMP, BLOCKS_LEFT
	cmp					EXTRA_BYTES, #0
	csinc				TMP, TMP, TMP, eq
	lsl					TMP, TMP, #4
    adds				OP2, x1, #(NUM_PRECOMPUTE_KEYS*16)
	subs				OP2, OP2, TMP
	ld1					{v0.16b}, [OP2]
	mov					v2.16b, SUM.16b
	karatsuba1_noload
	karatsuba2
	montgomery_reduction
	mov					SUM.16b, PH.16b
	eor					C.16b, C.16b, C.16b // Check if there's a faster zeroing method
	eor					D.16b, D.16b, D.16b // Check if there's a faster zeroing method
	eor					EF.16b, EF.16b, EF.16b // Check if there's a faster zeroing method
	mov					OP1, x0
	mov					IDX, XZR
.LoopPartial:
	cmp 				IDX, BLOCKS_LEFT
	bge 				.LoopExitPartial

	subs				TMP, IDX, BLOCKS_LEFT

	cmp					TMP, #-4
    bgt					.gt4Partial
	karatsuba1 4 0
	add					IDX, IDX, #4
    b					.outPartial

.gt4Partial:
	cmp					TMP, #-3
	bgt					.gt3Partial
	karatsuba1 3 0
	add					IDX, IDX, #3
    b					.outPartial

.gt3Partial:
	cmp					TMP, #-2
	bgt					.gt2Partial
	karatsuba1 2 0
	add					IDX, IDX, #2
    b					.outPartial

.gt2Partial:
	karatsuba1 1 0
	add					IDX, IDX, #1
.outPartial:
	b .LoopPartial
.LoopExitPartial:
	# Handle extra block
	cmp					EXTRA_BYTES, #0
	beq					.no_extra_block
	mov					OP1, x3
	karatsuba1 1 0
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
	eor					EF.16b, EF.16b, EF.16b // Check if there's a faster zeroing method
	mov					OP1, x0
	mov					OP2, x1
	karatsuba1 1 0
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

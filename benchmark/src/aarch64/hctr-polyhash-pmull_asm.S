/*
 * Copyright 2021 Google LLC
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 */
#include "asm_common.h"

#define NUM_PRECOMPUTE_KEYS 64

BLOCKS_LEFT	.req	x2 // Ensure caller saved, maybe switch
OP1			.req	x9 // Ensure caller saved, maybe switch
OP2			.req	x10 // Ensure caller saved, maybe switch
EXTRA_BYTES	.req	x11 // Ensure caller saved, maybe switch
IDX			.req	x12 // Ensure caller saved, maybe switch
TMP			.req	x13 // Ensure caller saved, maybe switch

PL			.req	v0
PH			.req	v1
T			.req	v2
Z			.req	v3
C			.req	v27
D			.req	v28
E			.req	v29
SUM			.req	v30
GSTAR		.req	v31

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
	.if \n == 4
		var_a1	.req v16
		var_a2	.req v17
		var_a3	.req v18
		var_a4	.req v19
	.endif
	.if \n == 5
		var_a1	.req v20
		var_a2	.req v21
		var_a3	.req v22
		var_a4	.req v23
	.endif
.endm

.macro karatsuba1 b
	.set by, \b

	.set i, 0
	.rept (by)
		setregs i
		ld1				{var_a1.16b}, [OP1]
		ext				var_a2.16b, var_a1.16b, var_a1.16b, #8
        add				OP1, OP1, #16
		.set i, (i +1)
	.endr

	.set i, 0
	.rept (by)
		setregs i
		ld1				{var_a3.16b}, [OP2]
		eor				var_a2.16b, var_a2.16b, var_a1.16b
        add				OP2, OP2, #16
		.set i, (i +1)
	.endr
	
    .set i, 0
	.rept (by)
		setregs i
		ext				var_a4.16b, var_a3.16b, var_a3.16b, #8
		.set i, (i +1)
	.endr

    .set i, 0
	.rept (by)
		setregs i
		eor				var_a4.16b, var_a4.16b, var_a3.16b
		.set i, (i +1)
	.endr

    .set i, 0
	.rept (by)
		setregs i
		pmull			var_a4.1q, var_a2.1d, var_a4.1d
		pmull2			var_a2.1q, var_a1.2d, var_a3.2d
		pmull			var_a1.1q, var_a1.1d, var_a3.1d
		.set i, (i +1)
	.endr
	
    .set i, 0
	.rept (by)
		setregs i
		eor				E.16b, E.16b, var_a4.16b
		eor				C.16b, C.16b, var_a2.16b
		eor				D.16b, D.16b, var_a1.16b
		.set i, (i +1)
	.endr
.endm

/*
 * Karatsuba1 without loading
 * Expects op1 in x0 and op2 in x2
 */
.macro karatsuba1_noload
		ext				v1.16b, v0.16b, v0.16b, #8
		eor				v1.16b, v1.16b, v0.16b
		ext				v3.16b, v2.16b, v2.16b, #8
		eor				v3.16b, v3.16b, v2.16b
		pmull			v3.1q, v1.1d, v3.1d
		pmull2			v1.1q, v0.2d, v2.2d
		pmull			v0.1q, v0.1d, v2.1d
		eor				E.16b, E.16b, v3.16b
		eor				C.16b, C.16b, v1.16b
		eor				D.16b, D.16b, v0.16b
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
	ld1					{v0.16b}, [x1]
	mov					v2.16b, SUM.16b
	karatsuba1_noload
	karatsuba2
	montgomery_reduction
	mov					SUM.16b, PH.16b
	eor					C.16b, C.16b, C.16b // Check if there's a faster zeroing method
	eor					D.16b, D.16b, D.16b // Check if there's a faster zeroing method
	eor					E.16b, E.16b, E.16b // Check if there's a faster zeroing method
	mov					OP1, x0
	mov					OP2, x1
	mov					IDX, XZR
.Loop:
	cmp 				IDX, #NUM_PRECOMPUTE_KEYS
	bge 				.LoopExit

	subs				TMP, IDX, #NUM_PRECOMPUTE_KEYS

	cmp					TMP, #-4
    bgt					.gt4
	karatsuba1 4
	add					IDX, IDX, #4
    b					.out

.gt4:
	cmp					TMP, #-3
	bgt					.gt3
	karatsuba1 3
	add					IDX, IDX, #3
    b					.out

.gt3:
	cmp					TMP, #-2
	bgt					.gt2
	karatsuba1 2
	add					IDX, IDX, #2
    b					.out

.gt2:
	karatsuba1 1
	add					IDX, IDX, #1
.out:
	b .Loop
.LoopExit:
	add					x0, x0, #(NUM_PRECOMPUTE_KEYS*16)
	karatsuba2
	montgomery_reduction
	eor					SUM.16b, SUM.16b, PH.16b
.endm

.macro partial_stride
	eor					C.16b, C.16b, C.16b // Check if there's a faster zeroing method
	eor					D.16b, D.16b, D.16b // Check if there's a faster zeroing method
	eor					E.16b, E.16b, E.16b // Check if there's a faster zeroing method
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
	eor					E.16b, E.16b, E.16b // Check if there's a faster zeroing method
	mov					OP1, x0
	mov					IDX, XZR
.LoopPartial:
	cmp 				IDX, BLOCKS_LEFT
	bge 				.LoopExitPartial

	subs				TMP, IDX, BLOCKS_LEFT

	cmp					TMP, #-4
    bgt					.gt4Partial
	karatsuba1 4
	add					IDX, IDX, #4
    b					.outPartial

.gt4Partial:
	cmp					TMP, #-3
	bgt					.gt3Partial
	karatsuba1 3
	add					IDX, IDX, #3
    b					.outPartial

.gt3Partial:
	cmp					TMP, #-2
	bgt					.gt2Partial
	karatsuba1 2
	add					IDX, IDX, #2
    b					.outPartial

.gt2Partial:
	karatsuba1 1
	add					IDX, IDX, #1
.outPartial:
	b .LoopPartial
.LoopExitPartial:
	# Handle extra block
	cmp					EXTRA_BYTES, #0
	beq					.no_extra_block
	mov					OP1, x3
	karatsuba1 1
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
 * void pmull_hctr2_mul(u128* op1, const u128* op2);
 */
ENTRY(pmull_hctr2_mul)
	adr					TMP, .Lgstar
	ld1					{GSTAR.2d}, [TMP]
	eor					C.16b, C.16b, C.16b // Check if there's a faster zeroing method
	eor					D.16b, D.16b, D.16b // Check if there's a faster zeroing method
	eor					E.16b, E.16b, E.16b // Check if there's a faster zeroing method
	mov					OP1, x0
	mov					OP2, x1
	karatsuba1 1
	karatsuba2
	montgomery_reduction
	st1					{PH.16b}, [x0]
	ret
ENDPROC(pmull_hctr2_mul)

/*
 * Perform polynomial evaluation as specified by HCTR2. Shifts the value stored
 * at accumulator by h^n and XORs the evaluated polynomial into it.
 *
 * Computes h^n*accumulator + h^nM_0 + ... + h^1M_{n-1} (No constant term)
 *
 * x0 (OP1) - pointer to message blocks
 * x1 - pointer to precomputed key struct
 * x2 - number of bytes to hash
 * x3 - final block (if nbytes % 16 != 0) used to allow padding without modifying *in
 * x4 - location to XOR with evaluated polynomial
 *
 * void pmull_hctr2_poly(const u128 *in, const struct polyhash_key* keys, uint64_t nbytes, const u128* final, u128* accumulator);
 */
ENTRY(pmull_hctr2_poly)
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
ENDPROC(pmull_hctr2_poly)

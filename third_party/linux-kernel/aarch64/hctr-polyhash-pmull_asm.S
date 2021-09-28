/*
 * Accelerated poly_hash implementation with ARMv8 PMULL instructions.
 *
 * Heavily modified version of ghash-ce-core.S.
 *
 * Copyright (C) 2014 Linaro Ltd. <ard.biesheuvel@linaro.org>
 * Copyright (C) 2017 Google LLC, <ebiggers@google.com>
 * Copyright (C) 2021 Google LLC, <nhuck@google.com>

 * Author: Nathan Huckleberry <nhuck@google.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation.
 */
#include "asm_common.h"
	GSTAR		.req	v31
	.text
	.align		4

	.arch		armv8-a+crypto
	/* 16-byte aligned (2**4 = 16); not required, but might as well */
	.align		4
.Lgstar:
	.quad		0x87, 0x87

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
	.if \n == 6
		var_a1	.req v24
		var_a2	.req v25
		var_a3	.req v26
		var_a4	.req v27
	.endif
	.if \n == 7
		var_a1	.req v28
		var_a2	.req v29
		var_a3	.req v30
		var_a4	.req v31
	.endif
.endm

/*
 * Used for computing 256-degree products of 128-degree polynomials
 *
 * Works on b pairs of operands at a time
 * Computes C, D and E as specified in algorithm 2 for each pair of operands
 * Leaves v0 as the bitwise XOR of all D
 * Leaves v1 as the bitwise XOR of all C
 * Leaves v3 as the bitwise XOR of all E
 * https://www.intel.cn/content/dam/www/public/us/en/documents/white-papers/carry-less-multiplication-instruction-in-gcm-mode-paper.pdf
 */
.macro pmull_xor_mul_no_reduction b
	.set by, \b

	.set i, 0
	.rept (by)
		setregs i
		ld1				{var_a1.16b}, [x0]
		ext				var_a2.16b, var_a1.16b, var_a1.16b, #8
        add				x0, x0, #16
		.set i, (i +1)
	.endr

	.set i, 0
	.rept (by)
		setregs i
		ld1				{var_a3.16b}, [x1]
		eor				var_a2.16b, var_a2.16b, var_a1.16b
        add				x1, x1, #16
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
	
    .set i, 1
	.rept (by - 1)
		setregs i
		eor				v3.16b, v3.16b, var_a4.16b
		eor				v1.16b, v1.16b, var_a2.16b
		eor				v0.16b, v0.16b, var_a1.16b
		.set i, (i +1)
	.endr
.endm

/*
 * Consider a 256-bit product is [C1 : P1 : P0 : D0].  It represents a
 * polynomial over GF(2) with degree as large as 255.  We need to
 * compute its remainder modulo g(x) = x^128+x^7+x^2+x+1.  For this it
 * is sufficient to compute the remainder of the high half 'c(x)x^128'
 * add it to the low half.  To reduce the high half we use the Barrett
 * reduction method.  The basic idea is that we can express the
 * remainder p(x) as g(x)q(x) mod x^128, where q(x) = (c(x)x^128)/g(x).
 * As detailed in [1], to avoid having to divide by g(x) at runtime the
 * following equivalent expression can be derived:
 *
 *	p(x) = [ g*(x)((c(x)q+(x))/x^128) ] mod x^128
 *
 * where g*(x) = x^128+g(x) = x^7+x^2+x+1, and q+(x) = x^256/g(x) = g(x)
 * in this case.  This is also equivalent to:
 *
 *	p(x) = [ g*(x)((c(x)(x^128 + g*(x)))/x^128) ] mod x^128
 *	     = [ g*(x)(c(x) + (c(x)g*(x))/x^128) ] mod x^128
 *
 * Since deg g*(x) < 64:
 *
 *	p(x) = [ g*(x)(c(x) + ((c(x)/x^64)g*(x))/x^64) ] mod x^128
 *	     = [ g*(x)((c(x)/x^64)x^64 + (c(x) mod x^64) +
 *				((c(x)/x^64)g*(x))/x^64) ] mod x^128
 *
 * Letting t(x) = g*(x)(c(x)/x^64):
 *
 *	p(x) = [ t(x)x^64 + g*(x)((c(x) mod x^64) + t(x)/x^64) ] mod x^128
 *
 * Therefore, to do the reduction we only need to issue two 64-bit =>
 * 128-bit carryless multiplications: g*(x) times c(x)/x^64, and g*(x)
 * times ((c(x) mod x^64) + t(x)/x^64).  (Multiplication by x^64 doesn't
 * count since it is simply a shift or move.)
 *
 * An alternate reduction method, also based on Barrett reduction and
 * described in [1], uses only shifts and XORs --- no multiplications.
 * However, the method with multiplications requires fewer instructions
 * and is faster on processors with fast carryless multiplication.
 *
 * [1] "Intel Carry-Less Multiplication Instruction and its Usage for
 * Computing the GCM Mode",
 * https://software.intel.com/sites/default/files/managed/72/cc/clmul-wp-rev-2.02-2014-04-20.pdf
 */

/*
 * This code is for computing reductions of polynomials modulo X^128 + X^7 + X^2 + X + 1
 * as specified above
 *
 * Reduces a 256-bit polynomial specified by (C, D, E) = (v1, v0, v3)
 * The resultant 128-bit polynomial is stored in v0
 */
.macro pmull_mul_reduction
		setregs 0
		adr				x3, .Lgstar
		ld1				{GSTAR.2d}, [x3]
		ext				var_a3.16b, var_a1.16b, var_a2.16b, #8
		eor				var_a4.16b, var_a4.16b, var_a3.16b
		eor				var_a3.16b, var_a1.16b, var_a2.16b
		eor				var_a3.16b, var_a4.16b, var_a3.16b
		pmull2			var_a4.1q, GSTAR.2d, var_a2.2d
		eor				var_a2.16b, var_a3.16b, var_a4.16b
		pmull2			var_a2.1q, GSTAR.2d, var_a2.2d
		eor				var_a1.16b, var_a1.16b, var_a2.16b
		eor				var_a3.16b, var_a3.16b, var_a4.16b
		ext				var_a2.16b, var_a2.16b, var_a2.16b, #8
		eor				var_a3.16b, var_a3.16b, var_a2.16b
		mov				var_a1.d[1], var_a3.d[0]
.endm

/*
 * void pmull_polyhash_mul(le128 *op1, const le128 *op2);
 */
ENTRY(pmull_polyhash_mul)
	pmull_xor_mul_no_reduction 1
    pmull_mul_reduction
    sub				x0, x0, #16
	st1				{v0.16b}, [x0]
	ret
ENDPROC(pmull_polyhash_mul)

/*
 * void pmull_polyhash_mul_xor(const le128 *op1_list, const le128 *op2_list, le128 *dst);
 */
ENTRY(pmull_polyhash_mul_xor)
	pmull_xor_mul_no_reduction 1
	ld1				{v4.16b}, [x2]
    add				x2, x2, #16
	ld1				{v5.16b}, [x2]
    add				x2, x2, #16
	ld1				{v6.16b}, [x2]
	eor				v4.16b, v4.16b, v1.16b
	eor				v5.16b, v5.16b, v0.16b
	eor				v6.16b, v6.16b, v3.16b
    sub				x2, x2, #32
	st1				{v4.16b}, [x2], #16
	st1				{v5.16b}, [x2], #16
	st1				{v6.16b}, [x2]
	ret
ENDPROC(pmull_polyhash_mul_xor)

/*
 * void pmull_polyhash_mul8_xor(const le128 *op1_list, const le128 *op2_list, le128 *dst);
 */
ENTRY(pmull_polyhash_mul4_xor)
	pmull_xor_mul_no_reduction 4
	ld1				{v4.16b}, [x2], #16
	ld1				{v5.16b}, [x2], #16
	ld1				{v6.16b}, [x2]
	eor				v4.16b, v4.16b, v1.16b
	eor				v5.16b, v5.16b, v0.16b
	eor				v6.16b, v6.16b, v3.16b
    sub				x2, x2, #32
	st1				{v4.16b}, [x2], #16
	st1				{v5.16b}, [x2], #16
	st1				{v6.16b}, [x2]
	ret
ENDPROC(pmull_polyhash_mul4_xor)

/*
 * void pmull_polyhash_xor_reduction(const le128 *in, le128 *out);
 */
ENTRY(pmull_polyhash_xor_reduction)
	ld1				{v1.16b}, [x0], #16
	ld1				{v0.16b}, [x0], #16
	ld1				{v3.16b}, [x0]
    pmull_mul_reduction
	ld1				{v1.16b}, [x1]
	eor				v0.16b, v0.16b, v1.16b
	st1				{v0.16b}, [x1]
	ret
ENDPROC(pmull_polyhash_mul4_xor)

/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * This implementation of GF multiplication is an adaptation
 * of the aarch64 implementation of HCTR.
 *
 * Accelerated polyhash implementation with Intel PCLMULQDQ-NI
 * instructions. This file contains accelerated part of polyhash
 * implementation. More information about PCLMULQDQ can be found at:
 *
 * http://software.intel.com/en-us/articles/carry-less-multiplication-and-its-usage-for-computing-the-gcm-mode/
 *
 * Copyright (C) 2021 Google LLC. <nhuck@google.com>
 *	 Author: Nathan Huckleberry <nhuck@google.com>
 */

#include "../asm_common.h"

.align 16

Lgstar:
	.quad 0x87, 0x87

/* generate a unique variable for xmm register */
.macro club_internal name, n
	\name = %xmm\n
.endm

/* club the numeric 'id' to the symbol 'name' */

.macro club id
.altmacro
	club_internal var_a1 %(\id*4)
	club_internal var_a2 %(\id*4+1)
	club_internal var_a3 %(\id*4+2)
	club_internal var_a4 %(\id*4+3)
.noaltmacro
.endm


.text

.macro clmul_xor_mul_no_reduction b
	.set by, \b

	.set i, 0
	.rept (by)
		club i
		movups (16*i)(%rdi), var_a1
		pshufd $0b01001110, var_a1, var_a3
		.set i, (i +1)
	.endr
	.set i, 0
	.rept (by)
		club i
		movups (16*i)(%rsi), var_a2
		pshufd $0b01001110, var_a2, var_a4
		.set i, (i +1)
	.endr
	.set i, 0
	.rept (by)
		club i
		pxor var_a1, var_a3
		pxor var_a2, var_a4
		.set i, (i +1)
	.endr
	.set i, 0
	.rept (by)
		club i
		pclmulqdq $0x00, var_a4, var_a3 # a3 = [A0 ^ A1] * [B0 ^ B1]
		movdqa var_a1, var_a4
		.set i, (i +1)
	.endr
	.set i, 0
	.rept (by)
		club i
		pclmulqdq $0x00, var_a2, var_a1 # a1 = [A0] * [B0]
		pclmulqdq $0x11, var_a4, var_a2 # a2 = [A1] * [B1]
		.set i, (i +1)
	.endr

	.set i, 1
	.rept (by - 1)
		club i
		pxor var_a1, %xmm0
		pxor var_a2, %xmm1
		pxor var_a3, %xmm2
		.set i, (i +1)
	.endr
.endm

#define GSTAR %xmm4
#define PL %xmm5
#define PH %xmm6
#define T %xmm7

/*
 * Reduces karatsuba parts into a polynomial mod X^128 + X^7 + X^2 + X + 1.
 * Leaves the reduced 128 bit polynomial in %xmm6
 * xmm1 = [C1 : C0]
 * xmm0 = [D1 : D0]
 * xmm2 = [E1 : E0]
 */
.macro clmul_mul_reduction
	vmovdqa Lgstar(%rip), GSTAR
	movdqa %xmm0, PL
	pxor %xmm1, PL
	pxor %xmm2, PL # [C1 ^ D1 ^ E1 : C0 ^ D0 ^ E0]
	movdqa PL, PH
	pslldq $8, PL # [C0 ^ D0 ^ E0 : 0]
	psrldq $8, PH # [0 : C1 ^ D1 ^ E1]
	pxor %xmm0, PL # [C0 ^ D0 ^ E0 ^ D1 : D0]
	pxor %xmm1, PH # c(x) = [C1 : C1 ^ D1 ^ E1 ^ C0] = [c(x) / x^64 : c(x) mod x^64]
	movdqa PH, T
	// t(x) = g*(x) * (c(x)/x^64)
	pclmulqdq $0x11, GSTAR, T # t(x) = [t(x) / x^64 : t(x) mod x^64]
	pslldq $8, PH # [c(x) mod x^64 : 0]
	pxor T, PH # [(c(x) mod x^64) + (t(x) / x^64) : JUNK]
	pclmulqdq $0x11, GSTAR, PH # g*(x)(c(x) mod x^64 + t(x)/x^64)
	pslldq $8, T # [t(x) * x^64 mod x^128]
	pxor T, PH
	pxor PL, PH

.endm

/* void clmul_polyhash_mul(char *dst, const u128 *op2) */
ENTRY(clmul_polyhash_mul)
	FRAME_BEGIN
	clmul_xor_mul_no_reduction 1
	clmul_mul_reduction
	movups %xmm6, (%rdi)
	FRAME_END
	ret
ENDPROC(clmul_polyhash_mul)

/* void clmul_polyhash_mul_xor(const u128 *op1, const u128 *op2, u128 * dst) */
ENTRY(clmul_polyhash_mul_xor)
	FRAME_BEGIN
	clmul_xor_mul_no_reduction 1
	movups (0*16)(%rdx), %xmm3
	movups (1*16)(%rdx), %xmm4
	movups (2*16)(%rdx), %xmm5
    pxor %xmm3, %xmm0
    pxor %xmm4, %xmm1
	pxor %xmm5, %xmm2
	movups %xmm0, (0*16)(%rdx)
	movups %xmm1, (1*16)(%rdx)
	movups %xmm2, (2*16)(%rdx)
	FRAME_END
	ret
ENDPROC(clmul_polyhash_mul_xor)

/* void clmul_polyhash_mul_xor(const u128 *op1, const u128 *op2, u128 * dst) */
ENTRY(clmul_polyhash_mul4_xor)
	FRAME_BEGIN
	clmul_xor_mul_no_reduction 4
	movups (0*16)(%rdx), %xmm3
	movups (1*16)(%rdx), %xmm4
	movups (2*16)(%rdx), %xmm5
    pxor %xmm3, %xmm0
    pxor %xmm4, %xmm1
	pxor %xmm5, %xmm2
	movups %xmm0, (0*16)(%rdx)
	movups %xmm1, (1*16)(%rdx)
	movups %xmm2, (2*16)(%rdx)
	FRAME_END
	ret
ENDPROC(clmul_polyhash_mul_xor)

/* void clmul_polyhash_mul_xor(const u128 *in, u128 * out) */
ENTRY(clmul_polyhash_xor_reduction)
	FRAME_BEGIN
	movups (0*16)(%rdi), %xmm0
	movups (1*16)(%rdi), %xmm1
	movups (2*16)(%rdi), %xmm2
	clmul_mul_reduction
	movups (%rsi), %xmm2
	pxor %xmm2, %xmm6
	movups %xmm6, (%rsi)
	FRAME_END
	ret
ENDPROC(clmul_polyhash_mul_xor)

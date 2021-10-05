 /*
 * Accelerated polyhash
 *
 * Copyright 2021 Google LLC
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 *
 * Author: Nathan Huckleberry <nhuck@google.com>
 */

#include "../asm_common.h"

.align 16

Lgstar:
	.quad 0xc200000000000000, 0xc200000000000000

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

.macro karatsuba1 b
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

#define PL %xmm5
#define PH %xmm6
.macro karatsuba2
	movdqa %xmm0, PL
	pxor %xmm1, PL
	pxor %xmm2, PL # [C1 ^ D1 ^ E1 : C0 ^ D0 ^ E0]
	movdqa PL, PH
	pslldq $8, PL # [C0 ^ D0 ^ E0 : 0]
	psrldq $8, PH # [0 : C1 ^ D1 ^ E1]
	pxor %xmm0, PL # [C0 ^ D0 ^ E0 ^ D1 : D0]
	pxor %xmm1, PH # c(x) = [C1 : C1 ^ D1 ^ E1 ^ C0] = [c(x) / x^64 : c(x) mod x^64]
.endm

#define GSTAR %xmm4
#define T %xmm7
#define Z %xmm8
.macro montgomery_reduction
	vmovdqa Lgstar(%rip), GSTAR
	movdqa PL, T
	pclmulqdq $0x00, GSTAR, T # T = [X0 * g*(x)]
	pshufd $0b01001110, T, Z # Z = [T0 : T1]
	pxor Z, PL # PL = [X1 ^ T0 : X0 ^ T1]
	pxor PL, PH # PH = [X1 ^ T0 ^ X3 : X0 ^ T1 ^ X2]
	pclmulqdq $0x11, GSTAR, PL # PL = [X1 ^ T0 * g*(x)]
	pxor PL, PH
.endm

/* void clmul_polyhash_mul(char *dst, const u128 *op2) */
ENTRY(clmul_polyhash_mul)
	FRAME_BEGIN
	karatsuba1 1
	karatsuba2
	montgomery_reduction
	movups %xmm6, (%rdi)
	FRAME_END
	ret
ENDPROC(clmul_polyhash_mul)

/* void clmul_polyhash_mul_xor(const u128 *op1, const u128 *op2, u128 * dst) */
ENTRY(clmul_polyhash_mul_xor)
	FRAME_BEGIN
	karatsuba1 1
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
	karatsuba1 4
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
	karatsuba2
	montgomery_reduction
	movups (%rsi), %xmm2
	pxor %xmm2, %xmm6
	movups %xmm6, (%rsi)
	FRAME_END
	ret
ENDPROC(clmul_polyhash_mul_xor)

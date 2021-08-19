// GHASH GF-multiplication with significant modifications

/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Accelerated GHASH implementation with Intel PCLMULQDQ-NI
 * instructions. This file contains accelerated part of polyhash
 * implementation. More information about PCLMULQDQ can be found at:
 *
 * http://software.intel.com/en-us/articles/carry-less-multiplication-and-its-usage-for-computing-the-gcm-mode/
 *
 * Copyright (c) 2009 Intel Corp.
 *	 Author: Huang Ying <ying.huang@intel.com>
 *		 Vinodh Gopal
 *		 Erdinc Ozturk
 *		 Deniz Karakoyunlu
 */

#include "../asm_common.h"

.align 16
byteswap_const:
	.octa 0x000102030405060708090A0B0C0D0E0F

#define OP1	%xmm0
#define OP2	%xmm1
#define T1	%xmm2
#define T2	%xmm3
#define T3	%xmm4
#define BSWAP	%xmm5
#define IN1	%xmm6

.text

/*
 * __clmul_gf128mul_ble:	internal ABI
 * input:
 *	OP1:			operand1
 *	OP2:			operand2
 * output:
 *	OP1:			operand1 * operand2 mod poly
 * changed:
 *	T1
 *	T2
 *	T3
 */
ENTRY(__clmul_gf128mul_ble)
	movdqa OP1, T1					#T1 = [A1 : A0]
	pshufd $0b01001110, OP1, T2		#T2 = [A0 : A1]
	pshufd $0b01001110, OP2, T3		#T3 = [B0 : B1]
	pxor OP1, T2					#[A0 ^ A1 : A0 ^ A1]
	pxor OP2, T3					#[B0 ^ B1 : B0 ^ B1]

	# Algorithm 2 from Carry-Less Multiplication Intel Paper
	pclmulqdq $0x00, OP2, OP1	# OP1 = [D1 : D0]
	pclmulqdq $0x11, OP2, T1	# T1 = [C1 : C0]
	pclmulqdq $0x00, T3, T2		# T2 = [E1 : E0]
	pxor OP1, T2
	pxor T1, T2			# T2 = [C1 ^ D1 ^ E1 : C0 ^ D0 ^ E0]

	movdqa T2, T3
	pslldq $8, T3		# T3 = [C0 ^ D0 ^ E0 : 0]
	psrldq $8, T2		# T2 = [0 : C1 ^ D1 ^ E1]
	pxor T3, OP1		# OP1 = [C0 ^ D0 ^ E0 ^ D1 : D0] (127 degree polynomial part)
	pxor T2, T1			# T1 = [C1 : C1 ^ D1 ^ E1 ^ C0] (255 degree polynomial part)

    # Following instructions reduce T1 mod an irreducible polynomial
	# Modified algorithm 4 from Carry-Less Multiplication Intel Paper
	# first phase of the reduction
	movdqa T1, T3				# T3 = [X3 : X2]
	psrlq $1, T3				# T3 = [X3 >> 1 : Junk]
	pxor T1, T3
	psrlq $5, T3				# T3 = [X3 >> 6 ^ X3 >> 5 : Junk]
	pxor T1, T3
	psrlq $57, T3				# T3 = [X3 >> 63 ^ X3 >> 62 ^ X3 >> 57 : Junk] = [A ^ B ^ C : Junk]
	psrldq $8, T3
	pxor T1, T3					# T3 = [X3 : A ^ B ^ C ^ X2] = [X3 : D]

	# second phase of the reduction
	movdqa T3, T1				# T1 = [X3 : D]
	movdqa T3, T2				# T2 = [X3 : D]
	psllq $5, T2
	pxor T1, T2					# T2 = [X3 : D] << 5 ^ [X3 : D]
	psllq $1, T2
	pxor T1, T2					# T2 = [X3 : D] << 6 ^ [X3 : D] << 1 ^ [X3 : D]
	psllq $1, T2				# T2 = [X3 : D] << 7 ^ [X3 : D] << 2 ^ [X3 : D] << 1
    pxor T1, T2					# T2 = [H1 : H0] (minus some shifting issues)
    # psllq shifts independently on two 64-bit values, so
    # we need to account for shifting from high qw to low qw
    # T1 = T3 = [X3 : D]
	psrlq $1, T3				# T3 = [Junk : D >> 1]
	pxor T1, T3
	psrlq $5, T3				# T3 = [Junk : D >> 6 ^ D >> 5]
	pxor T1, T3
	psrlq $57, T3				# T3 = [Junk : D >> 63 ^ D >> 62 ^ D >> 57]
	pslldq $8, T3               # T3 = [D >> 63 ^ D >> 62 ^ D >> 57]
    pxor T3, T2
	pxor T2, OP1
	ret
ENDPROC(__clmul_gf128mul_ble)

/* void clmul_polyhash_mul(char *dst, const u128 *op2) */
ENTRY(clmul_polyhash_mul)
	FRAME_BEGIN
	movups (%rdi), OP1
	movups (%rsi), OP2
	call __clmul_gf128mul_ble
	movups OP1, (%rdi)
	FRAME_END
	ret
ENDPROC(clmul_polyhash_mul)

/* void clmul_polyhash_mul_xor(const u128 *op1, const u128 *op2, u128 * dst) */
ENTRY(clmul_polyhash_mul_xor)
	FRAME_BEGIN
	movups (%rdi), OP1
	movups (%rsi), OP2
	call __clmul_gf128mul_ble
	movups (%rdx), OP2
    pxor OP2, OP1
	movups OP1, (%rdx)
	FRAME_END
	ret
ENDPROC(clmul_polyhash_mul_xor)

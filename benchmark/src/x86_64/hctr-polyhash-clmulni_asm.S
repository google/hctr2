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

#define PL %xmm0
#define PH %xmm1
#define T %xmm2
#define Z %xmm3
#define GSTAR %xmm4
#define C %xmm12
#define D %xmm13
#define E %xmm14
#define SUM %xmm15

#define BLOCKS_LEFT %rdx
#define OP1 %rdi
#define EXTRA_BYTES %r9
#define OP2 %r10
#define IDX %r11
#define TMP %rax

#define NUM_PRECOMPUTE_KEYS 64

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

/*
 * Accepts operand lists of length b in rdi and rsi. Computes the product of
 * each rdi,rsi pair then XORs the products into C, D, E.
 *
 * XORs product into C, D, E
 * Preserves SUM
 * All other xmm registers clobbered
 */
.macro karatsuba1 b
	.set by, \b

	.set i, 0
	.rept (by)
		club i
		movups (16*i)(OP1), var_a1
		pshufd $0b01001110, var_a1, var_a3
		.set i, (i +1)
	.endr
	.set i, 0
	.rept (by)
		club i
		movups (16*i)(OP2), var_a2
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

	.set i, 0
	.rept (by)
		club i
		pxor var_a1, D
		pxor var_a2, C
		pxor var_a3, E
		.set i, (i +1)
	.endr
.endm

/*
 * Computes first karatsuba step of values loaded into xmm0 and xmm1. Used to
 * multiply intermediate register values rather than memory stored values.
 *
 * XORs product into C, D, E
 * Preserves SUM
 * All other xmm registers clobbered
 */
.macro karatsuba1_noload
	pshufd $0b01001110, %xmm0, %xmm2
	pshufd $0b01001110, %xmm1, %xmm3
	pxor %xmm0, %xmm2
	pxor %xmm1, %xmm3
	pclmulqdq $0x00, %xmm3, %xmm2
	movdqa %xmm0, %xmm3
	pclmulqdq $0x00, %xmm1, %xmm0
	pclmulqdq $0x11, %xmm3, %xmm1
	pxor %xmm0, D
	pxor %xmm1, C
	pxor %xmm2, E
.endm

/*
 * Computes the 256-bit polynomial represented by C, D, E. Stores
 * the result in PL, PH.
 *
 * All other xmm registers are preserved.
 */
.macro karatsuba2
	movdqa C, PL
	pxor D, PL
	pxor E, PL # [C1 ^ D1 ^ E1 : C0 ^ D0 ^ E0]
	movdqa PL, PH
	pslldq $8, PL # [C0 ^ D0 ^ E0 : 0]
	psrldq $8, PH # [0 : C1 ^ D1 ^ E1]
	pxor D, PL # [C0 ^ D0 ^ E0 ^ D1 : D0]
	pxor C, PH # c(x) = [C1 : C1 ^ D1 ^ E1 ^ C0] = [c(x) / x^64 : c(x) mod x^64]
.endm

/*
 * Computes the 128-bit reduction of PL, PH. Stores the result in PH.
 * 
 * PL, PH, Z, T.
 * All other xmm registers are preserved.
 */
.macro montgomery_reduction
	movdqa PL, T
	pclmulqdq $0x00, GSTAR, T # T = [X0 * g*(x)]
	pshufd $0b01001110, T, Z # Z = [T0 : T1]
	pxor Z, PL # PL = [X1 ^ T0 : X0 ^ T1]
	pxor PL, PH # PH = [X1 ^ T0 ^ X3 : X0 ^ T1 ^ X2]
	pclmulqdq $0x11, GSTAR, PL # PL = [X1 ^ T0 * g*(x)]
	pxor PL, PH
.endm

/*
 * Compute poly on window size of NUM_PRECOMPUTE_KEYS blocks
 * Poly = M_0h^N + ... + M_{n-1}h^1 (no constant term)
 */
.macro full_stride
	pxor C, C
	pxor D, D
	pxor E, E
	mov %rsi, OP2
	# Multiply sum by h^N
	movups (%rsi), %xmm0
	movdqa SUM, %xmm1
	karatsuba1_noload
	karatsuba2
	montgomery_reduction
	movdqa PH, SUM
	pxor C, C
	pxor D, D
	pxor E, E
	xor IDX, IDX
.Loop:
	cmpq $(NUM_PRECOMPUTE_KEYS), IDX
	jae .LoopExit
	
	movq $(NUM_PRECOMPUTE_KEYS), TMP
	subq IDX, TMP

	cmp $3, TMP # TMP < 3 ?
	jl .lt3
	karatsuba1 3
	addq $3, IDX
	addq $(3*16), OP1
	addq $(3*16), OP2
	jmp .out
.lt3:
	cmp $2, TMP # TMP < 2 ?
	jl .lt2
	karatsuba1 2
	addq $2, IDX
	addq $(2*16), OP1
	addq $(2*16), OP2
	jmp .out
.lt2:
	karatsuba1 1 # TMP < 1 ?
	addq $1, IDX
	addq $(1*16), OP1
	addq $(1*16), OP2
.out:
	jmp .Loop
.LoopExit:
	karatsuba2
	montgomery_reduction
	pxor PH, SUM
.endm

/*
 * Compute poly on window size of %rdx blocks
 * 0 < %rdx < NUM_PRECOMPUTE_KEYS
 */
.macro partial_stride
	pxor C, C
	pxor D, D
	pxor E, E
	mov BLOCKS_LEFT, TMP
	test EXTRA_BYTES, EXTRA_BYTES
	je .no_extra_block1
	inc TMP
.no_extra_block1:
	shlq $4, TMP
	mov %rsi, OP2
	addq $(16*NUM_PRECOMPUTE_KEYS), OP2
	subq TMP, OP2
	# Multiply sum by h^N
	movups (OP2), %xmm0
	movdqa SUM, %xmm1
	karatsuba1_noload
	karatsuba2
	montgomery_reduction
	movdqa PH, SUM
	pxor C, C
	pxor D, D
	pxor E, E
	xor IDX, IDX
.LoopPartial:
	cmpq BLOCKS_LEFT, IDX # IDX < rdx
	jae .LoopExitPartial
	
	movq BLOCKS_LEFT, TMP
	subq IDX, TMP # TMP = rdx - IDX

	cmp $3, TMP # TMP < 3 ?
	jl .lt3Partial
	karatsuba1 3
	addq $3, IDX
	addq $(3*16), OP1
	addq $(3*16), OP2
	jmp .outPartial
.lt3Partial:
	cmp $2, TMP # TMP < 2 ?
	jl .lt2Partial
	karatsuba1 2
	addq $2, IDX
	addq $(2*16), OP1
	addq $(2*16), OP2
	jmp .outPartial
.lt2Partial:
	karatsuba1 1 # TMP < 1 ?
	addq $1, IDX
	addq $(1*16), OP1
	addq $(1*16), OP2
.outPartial:
	jmp .LoopPartial
.LoopExitPartial:
	# Handle extra block
	test EXTRA_BYTES, EXTRA_BYTES
	je .no_extra_block2
	movq %rcx, OP1
	karatsuba1 1
.no_extra_block2:
	karatsuba2
	montgomery_reduction
	pxor PH, SUM
.endm

/*
 * Perform montgomery multiplication in GF128 and store result in op1.
 *
 * Computes op1*op2*x^{-128} mod x^128 + x^127 + x^126 + x^121 + 1
 *
 * void clmul_hctr2_mul(u128* op1, const u128* op2);
 */
ENTRY(clmul_hctr2_mul)
	FRAME_BEGIN
	vmovdqa Lgstar(%rip), GSTAR
	pxor C, C
	pxor D, D
	pxor E, E
	mov %rsi, OP2
	karatsuba1 1
	karatsuba2
	montgomery_reduction
	movups PH, (%rdi)
	FRAME_END
	ret
ENDPROC(clmul_hctr2_mul)

/* 
 * Perform polynomial evaluation as specified by HCTR2. Shifts the value stored
 * at accumulator by h^n and XORs the evaluated polynomial into it.
 *
 * Computes h^n*accumulator + h^nM_0 + ... + h^1M_{n-1} (No constant term)
 *
 * rdi (OP1) - pointer to message blocks
 * rsi - pointer to precomputed key struct
 * rdx - number of bytes to hash
 * rcx - final block (if nbytes % 16 != 0) used to allow padding without modifying *in
 * r8 - location to XOR with evaluated polynomial
 * 
 * void clmul_hctr2_poly(const u128 *in, const struct polyhash_key* keys, uint64_t nbytes, const u128* final, u128* accumulator);
 */
ENTRY(clmul_hctr2_poly)
	FRAME_BEGIN
	vmovdqa Lgstar(%rip), GSTAR
	movq $0x0f, EXTRA_BYTES
	andq BLOCKS_LEFT, EXTRA_BYTES
	shr $4, BLOCKS_LEFT
	movups (%r8), SUM
.StrideLoop:
	cmpq $NUM_PRECOMPUTE_KEYS, BLOCKS_LEFT
	jb .StrideLoopExit
	full_stride
	subq $NUM_PRECOMPUTE_KEYS, BLOCKS_LEFT
	jmp .StrideLoop
.StrideLoopExit:
	test BLOCKS_LEFT, BLOCKS_LEFT
	jne .DoPartial
	test EXTRA_BYTES, EXTRA_BYTES
	jne .DoPartial
	jmp .SkipPartial
.DoPartial:
	partial_stride
.SkipPartial:
	movups SUM, (%r8)
	FRAME_END
	ret
ENDPROC(clmul_hctr2_poly)

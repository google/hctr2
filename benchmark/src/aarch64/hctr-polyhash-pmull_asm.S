
/*
 * Accelerated poly_hash implementation with ARMv8 PMULL instructions.
 *
 * Based on ghash-ce-core.S.
 *
 * Copyright (C) 2014 Linaro Ltd. <ard.biesheuvel@linaro.org>
 * Copyright (C) 2017 Google, Inc. <ebiggers@google.com>
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

.macro calc n i
	\n*4+i
.endm

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
.endm

.macro pmull_xor_mul b
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

		adr				x1, .Lgstar
		ld1				{GSTAR.2d}, [x1]

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
		ext				var_a3.16b, var_a1.16b, var_a2.16b, #8
		.set i, (i +1)
	.endr

	.set i, 0
	.rept (by)
		setregs i
		eor				var_a4.16b, var_a4.16b, var_a3.16b
		eor				var_a3.16b, var_a1.16b, var_a2.16b
		.set i, (i +1)
	.endr

	.set i, 0
	.rept (by)
		setregs i
		eor				var_a3.16b, var_a4.16b, var_a3.16b
		pmull2			var_a4.1q, GSTAR.2d, var_a2.2d
		.set i, (i +1)
	.endr

	.set i, 0
	.rept (by)
		setregs i
		eor				var_a2.16b, var_a3.16b, var_a4.16b
		.set i, (i +1)
	.endr

	.set i, 0
	.rept (by)
		setregs i
		pmull2			var_a2.1q, GSTAR.2d, var_a2.2d
		.set i, (i +1)
	.endr

	.set i, 0
	.rept (by)
		setregs i
		eor				var_a1.16b, var_a1.16b, var_a2.16b
		eor				var_a3.16b, var_a3.16b, var_a4.16b
		ext				var_a2.16b, var_a2.16b, var_a2.16b, #8
		.set i, (i +1)
	.endr

	.set i, 0
	.rept (by)
		setregs i
		eor				var_a3.16b, var_a3.16b, var_a2.16b
		mov				var_a1.d[1], var_a3.d[0]
		.set i, (i +1)
	.endr

	.set i, 1
	.rept (by - 1)
		setregs i
		eor				v0.16b, v0.16b, var_a1.16b
		.set i, (i +1)
	.endr
.endm

/*
 * void pmull_polyhash_mul(le128 *op1, const le128 *op2);
 */
ENTRY(pmull_polyhash_mul)
	pmull_xor_mul 1
    sub				x0, x0, #16
	st1				{v0.16b}, [x0]
	ret
ENDPROC(pmull_polyhash_mul)

/*
 * void pmull_polyhash_mul_xor(const le128 *op1_list, const le128 *op2_list, le128 *dst);
 */
ENTRY(pmull_polyhash_mul_xor)
	pmull_xor_mul 1
	ld1				{v1.16b}, [x2]
	eor				v0.16b, v0.16b, v1.16b
	st1				{v0.16b}, [x2]
	ret
ENDPROC(pmull_polyhash_mul_xor)

/*
 * void pmull_polyhash_mul8_xor(const le128 *op1_list, const le128 *op2_list, le128 *dst);
 */
ENTRY(pmull_polyhash_mul4_xor)
	pmull_xor_mul 4
	ld1				{v1.16b}, [x2]
	eor				v0.16b, v0.16b, v1.16b
	st1				{v0.16b}, [x2]
	ret
ENDPROC(pmull_polyhash_mul4_xor)

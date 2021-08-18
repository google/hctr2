
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
	A1		.req	v0
	A2		.req	v1
	A3		.req	v2
	A4		.req	v3
	GSTAR	.req	v4
	.text
    .align		4

    .arch		armv8-a+crypto
	/* 16-byte aligned (2**4 = 16); not required, but might as well */
	.align		4
.Lgstar:
	.quad		0x87, 0x87
/*
 * void pmull_poly_hash_update(le128 *dst, const le128 *src);
 */
ENTRY(pmull_polyhash_mul)
    ld1             {A1.16b}, [x0]
    ext             A2.16b, A1.16b, A1.16b, #8
    eor             A2.16b, A2.16b, A1.16b
    ld1             {A3.16b}, [x1]
    ext             A4.16b, A3.16b, A3.16b, #8
    eor             A4.16b, A4.16b, A3.16b
    adr             x1, .Lgstar
    ld1             {GSTAR.2d}, [x1]
    pmull           A4.1q, A2.1d, A4.1d
    pmull2          A2.1q, A1.2d, A3.2d
    pmull           A1.1q, A1.1d, A3.1d
    ext             A3.16b, A1.16b, A2.16b, #8
    eor             A4.16b, A4.16b, A3.16b
    eor             A3.16b, A1.16b, A2.16b
    eor             A3.16b, A4.16b, A3.16b
    pmull2          A4.1q, GSTAR.2d, A2.2d
    eor             A2.16b, A3.16b, A4.16b
    pmull2          A2.1q, GSTAR.2d, A2.2d
    eor             A1.16b, A1.16b, A2.16b
    eor             A3.16b, A3.16b, A4.16b
    ext             A2.16b, A2.16b, A2.16b, #8
    eor             A3.16b, A3.16b, A2.16b
    mov             A1.d[1], A3.d[0]
    st1             {A1.16b}, [x0]
    ret
ENDPROC(pmull_polyhash_mul)

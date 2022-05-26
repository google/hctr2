/*
 * Copyright 2018 Google LLC
 *
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 */
#pragma once

#include "cbconfig.h"

// clang-format off

#if SYMBOLS_HAVE_UNDERSCORE_PREFIX
#define CDECL_NAME(name) _##name
#else
#define CDECL_NAME(name) name
#endif

#define SYM_FUNC_START(name) \
	.globl CDECL_NAME(name); \
	CDECL_NAME(name):

#define SYM_FUNC_START_LOCAL(name) \
	CDECL_NAME(name):

#define SYM_FUNC_ALIAS_LOCAL(alias, name) \
	.set alias, name; \
	.type alias STT_FUNC;

#if defined(__linux__)
#define SYM_FUNC_END(name) \
    .type CDECL_NAME(name), %function; \
    .size CDECL_NAME(name), . - CDECL_NAME(name)
#else
#define SYM_FUNC_END(name)
#endif

#ifdef __x86_64__
.macro FRAME_BEGIN
	push %rbp
	mov %rsp, %rbp
.endm
.macro FRAME_END
	pop %rbp
.endm
#elif defined(__aarch64__)
.macro cond_yield, lbl:req, tmp:req, tmp2:req
.endm

.macro adr_l, dst, sym
	adrp \dst, \sym
	add \dst, \dst, :lo12:\sym
.endm

/* Needed for older binutils versions */
.macro bti, targets
.ifc \targets,c
	hint 34
.else
	.error "Unhandled bti target"
.endif
.endm
#endif /* __aarch64__ */

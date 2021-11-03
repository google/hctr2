/*
 * Copyright (C) 2018 Google LLC
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

#define ENTRY(name)    .globl CDECL_NAME(name); CDECL_NAME(name):
#if defined(__linux__)
#define ENDPROC(name)	\
    .type CDECL_NAME(name), %function; \
    .size CDECL_NAME(name), . - CDECL_NAME(name)
#else
#define ENDPROC(name)
#endif

#ifdef __x86_64__
.macro FRAME_BEGIN
	push %rbp
	mov %rsp, %rbp
.endm
.macro FRAME_END
	pop %rbp
.endm
#endif

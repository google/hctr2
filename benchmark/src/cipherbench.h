/*
 * Copyright (C) 2018 Google LLC
 *
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 */
#pragma once

void test_hctr2_hash(void);
void test_hctr2_ctr(void);
void test_hctr2(void);
void test_xts(void);

void do_insn_timing(void);

struct cipherbench_params {
	int bufsize;
	int ntries;
};

extern struct cipherbench_params g_params;

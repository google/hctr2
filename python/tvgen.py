# Copyright 2018 Google LLC
#
# Use of this source code is governed by an MIT-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/MIT.

import inputgen
import tvstore


def generate_testvectors(cipher):
    for lengths in cipher.test_input_lengths():
        print(lengths)
        for tv, d in inputgen.generate_testinputs(lengths):
            yield cipher.make_testvector(tv, d)


def write_tests(args, cipher):
    tv_store = tvstore.TvStore(args.test_vectors)
    for v in cipher.variants():
        cipher.variant = v
        print(f"======== {cipher.variant_name()} ========")
        tv_store.write(cipher, generate_testvectors(cipher))


def check_testvector(cipher, tv, verbose):
    cipher.check_testvector(tv)
    if verbose:
        print(f"OK: {tv['description']}")


def check_tests(args, cipher):
    print(f"======== {cipher.variant_name()} ========")
    tv_store = tvstore.TvStore(args.test_vectors)
    for tv in tv_store.iter_read(cipher):
        check_testvector(cipher, tv, args.verbose)

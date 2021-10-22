# Copyright 2018 Google LLC
#
# Use of this source code is governed by an MIT-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/MIT.

import hexjson

import inputgen


def generate_testvectors(cipher):
    for lengths in cipher.test_input_lengths():
        print(lengths)
        for tv, d in inputgen.generate_testinputs(lengths):
            yield cipher.make_testvector(tv, d)


def write_tests(tvstore, cipher):
    for v in cipher.variants():
        cipher.variant = v
        p = tvstore.path(cipher)
        print(f"Writing: {p}")
        hexjson.write_using_hex(p, generate_testvectors(cipher))


def check_testvector(cipher, tv, verbose):
    cipher.check_testvector(tv)
    if verbose:
        print(f"OK: {tv['description']}")


def check_tests(tvstore, cipher, verbose):
    fn = tvstore.path(cipher)
    print(f"======== {fn.name} ========")
    for tv in hexjson.iter_unhex(fn):
        check_testvector(cipher, tv, verbose)

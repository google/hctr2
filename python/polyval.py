# Copyright 2021 Google LLC
#
# Use of this source code is governed by an MIT-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/MIT.

import cipher
import gf


class Hash(cipher.Cipher):
    def make_testvector(self, input, description):
        return {
            'cipher': self.variant,
            'description': description,
            'input': input,
            'hash': self.hash(**input),
        }

    def check_testvector(self, tv):
        self.variant = tv['cipher']
        assert tv['hash'] == self.hash(**tv['input'])


class Polyval(Hash):
    _has_external_testvectors = True
    
    def __init__(self):
        super().__init__()
        self.gf = gf.GF(["X^128", "X^127", "X^126", "X^121", "X^0"])
        self.polyval_const = self.gf(
            (1 << 127) | (
                1 << 124) | (
                1 << 121) | (
                1 << 114) | (1))
        self.choose_variant(lambda x: True)

    def variant_name(self):
        return self.name()

    def variants(self):
        yield {
            'cipher': 'Polyval',
            'lengths': {
                'key': 16,
                'block': 16,
                'output': 16,
            }
        }

    def test_input_lengths(self):
        v = dict(self.lengths())
        del v["block"]
        del v["output"]
        for mlen in range(0, 80, 16):
            yield {**v, "message": mlen}

    def hash(self, key, message):
        blocksize = self.lengths()['block']
        assert len(message) % blocksize == 0
        hgen = self.gf.from_bytes(key, byteorder="little")
        hpoly = hgen * self.polyval_const
        hash_result = self.gf(0)
        for i in range(0, len(message), blocksize):
            hash_result += self.gf.from_bytes(
                message[i:i + blocksize], byteorder='little')
            hash_result *= hpoly
        return hash_result.to_bytes(byteorder='little')

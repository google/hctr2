# Copyright 2021 Google LLC
#
# Use of this source code is governed by an MIT-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/MIT.

import cipher
import gf
import test_polyval


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
    def __init__(self):
        super().__init__()
        self.gf = gf.GF([128, 127, 126, 121, 0])
        self.polyval_const = self.gf.from_int(
            sum(1 << x for x in [127, 124, 121, 114, 0]))
        self.choose_variant(lambda x: True)

    def variant_name(self):
        return self.name()

    def variants(self):
        yield {
            'cipher': 'Polyval',
            'lengths': {
                'key': self.gf.blocksize,
            }
        }

    def test_input_lengths(self):
        v = dict(self.lengths())
        for mlen in range(0, 80, 16):
            yield {**v, "message": mlen}

    def hash(self, key, message):
        blocksize = self.lengths()['key']
        assert len(message) % blocksize == 0
        hgen = self.gf.from_bytes(key, byteorder="little")
        hpoly = hgen * self.polyval_const
        hash_result = self.gf.from_int(0)
        for i in range(0, len(message), blocksize):
            hash_result += self.gf.from_bytes(
                message[i:i + blocksize], byteorder='little')
            hash_result *= hpoly
        return hash_result.to_bytes(byteorder='little')

    def other_testvectors(self, tvdir):
        for tv in test_polyval.parse_tvs(tvdir):
            yield {
                'cipher': self.variant,
                'description': "From RFC",
                'input': {
                    'key': tv['Record authentication key'],
                    'message': tv['POLYVAL input'],
                },
                'hash': tv['POLYVAL result'],
            }

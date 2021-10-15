# Copyright 2021 Google LLC
#
# Use of this source code is governed by an MIT-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/MIT.

import itertools

from Crypto.Util.strxor import strxor

import aes
import cipher


class XCTR(cipher.Cipher):
    def __init__(self):
        self._block = aes.AES()

    def _setup_variant(self):
        self._block.variant = self.variant['blockcipher']
        return super()._setup_variant()

    def variant_name(self):
        return "{}_{}".format(self.name(),
                              self._block.variant_name())

    def variants(self):
        for bs in self._block.variants():
            yield {
                'cipher': self.name(),
                'blockcipher': bs,
                'lengths': {
                    'key': bs['lengths']['key'],
                    'nonce': bs['lengths']['block'],
                }}

    def gen(self, l, nonce, key):
        assert len(key) == self.lengths()['key']
        assert len(nonce) == self.lengths()['nonce']
        res = b''
        for i in itertools.count(1):
            block = strxor(nonce, i.to_bytes(len(nonce), byteorder='little'))
            res += self._block.encrypt(block, key)
            if len(res) >= l:
                return res[:l]

    _test_length = 47

    def make_testvector(self, input, description):
        input['l'] = self._test_length
        return {
            "cipher": self.variant,
            "description": description,
            "input": input,
            "output": self.gen(**input)
        }

    def check_testvector(self, tv):
        self.variant = tv["cipher"]
        assert tv["output"] == self.gen(**tv["input"])

# Copyright 2021 Google LLC
#
# Use of this source code is governed by an MIT-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/MIT.

import Crypto.Util.strxor

import ciphers.aes
import ciphers.cipher


def strxor(a, b):
    assert len(a) == len(b)
    # Crypto.Util.strxor craps out on zero length input :(
    if len(a) == 0:
        return b''
    return Crypto.Util.strxor.strxor(a, b)


class XCTR(ciphers.cipher.Bijection):
    def __init__(self):
        self._block = ciphers.aes.AES()

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
        count = 0
        while len(res) < l:
            count += 1
            countblock = count.to_bytes(len(nonce), byteorder='little')
            res += self._block.encrypt(strxor(nonce, countblock), key)
        return res[:l]

    # encrypt and decrypt are the same
    def encrypt(self, plaintext, nonce, key):
        return strxor(plaintext, self.gen(len(plaintext), nonce, key))

    def decrypt(self, ciphertext, nonce, key):
        return strxor(ciphertext, self.gen(len(ciphertext), nonce, key))

    def test_input_lengths(self):
        v = dict(self.lengths())
        lengths = {
            16: [1, 16, 31, 128, 255],
            24: [15, 17, 48, 512],
            32: [1, 15, 16, 17, 31, 48, 128, 255, 512]
        }
        for l in lengths[v['key']]:
            for m in "plaintext", "ciphertext":
                yield {**v, m: l}

    def testvec_fields(self):
        return ['key', 'nonce', 'plaintext', 'ciphertext']

    def convert_testvec(self, v):
        return {
            'key': v['input']['key'],
            'nonce': v['input']['nonce'],
            'plaintext': v['plaintext'],
            'ciphertext': v['ciphertext'],
        }

    def linux_convert_testvec(self, v):
        return {
            'key': v['input']['key'],
            'iv': v['input']['nonce'],
            'ptext': v['plaintext'],
            'ctext': v['ciphertext'],
            'klen': len(v['input']['key']),
            'len': len(v['plaintext']),
            'description': None
        }

    def linux_name(self):
        return f"{self._block.name()}_{self.name()}"

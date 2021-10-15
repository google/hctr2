# Copyright 2021 Google LLC
#
# Use of this source code is governed by an MIT-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/MIT.

import Crypto.Util.strxor

import aes
import cipher
import polyval
import xctr


def strxor(a, b):
    assert len(a) == len(b)
    # Crypto.Util.strxor craps out on zero length input :(
    if len(a) == 0:
        return b''
    return Crypto.Util.strxor.strxor(a, b)


class HCTR2(cipher.Blockcipher):
    def __init__(self):
        self._block = aes.AES()
        self._polyval = polyval.Polyval()
        self._xctr = xctr.XCTR()

    def _setup_variant(self):
        bc = self.variant['blockcipher']
        self._block.variant = bc
        self._xctr.choose_variant(lambda v: v['blockcipher'] == bc)
        assert bc['lengths']['block'] == self._polyval.lengths()['key']
        return super()._setup_variant()

    def variant_name(self):
        return "{}_{}".format(self.name(),
                              self._block.variant_name())

    def variants(self):
        for bs in self._block.variants():
            assert bs['lengths']['block'] == self._polyval.lengths()['key']
            yield {
                'cipher': self.name(),
                'blockcipher': bs,
                'lengths': bs['lengths'],
            }

    def _pad(self, l, s):
        return s + b'\x00' * ((-len(s)) % l)

    def _hash(self, hash_key, message, tweak):
        blocksize = self.lengths()['block']
        awkward = len(message) % blocksize != 0
        lengthint = len(tweak) * 8 * 2 + 2
        if awkward:
            lengthint += 1
        blocks = lengthint.to_bytes(blocksize, byteorder='little')
        blocks += self._pad(blocksize, tweak)
        if awkward:
            blocks += self._pad(blocksize, message + b'\x01')
        else:
            blocks += message
        return self._polyval.hash(hash_key, blocks)

    def _gen(self, key, i):
        b = i.to_bytes(self.lengths()['block'], byteorder='little')
        return self._block.encrypt(b, key=key)

    def encrypt(self, pt, key, tweak):
        assert len(key) == self.lengths()['key']
        assert len(pt) >= self.lengths()['block']
        hash_key = self._gen(key, 0)
        l = self._gen(key, 1)
        m = pt[0:16]
        n = pt[16:]
        mm = strxor(m, self._hash(hash_key, n, tweak))
        uu = self._block.encrypt(mm, key=key)
        s = strxor(strxor(mm, uu), l)
        v = strxor(n, self._xctr.gen(len(n), nonce=s, key=key))
        u = strxor(uu, self._hash(hash_key, v, tweak))
        return u + v

    def decrypt(self, ct, key, tweak):
        assert len(key) == self.lengths()['key']
        assert len(ct) >= self.lengths()['block']
        hash_key = self._gen(key, 0)
        l = self._gen(key, 1)
        u = ct[0:16]
        v = ct[16:]
        uu = strxor(u, self._hash(hash_key, v, tweak))
        mm = self._block.decrypt(uu, key=key)
        s = strxor(strxor(mm, uu), l)
        n = strxor(v, self._xctr.gen(len(v), nonce=s, key=key))
        m = strxor(mm, self._hash(hash_key, n, tweak))
        return m + n

    def test_input_lengths(self):
        v = dict(self.lengths())
        b = v['block']
        del v['block']
        for t in [0, 1, 16, 32, 47]:
            for l in [16, 17, 32, 33]:
                for m in "plaintext", "ciphertext":
                    yield {**v, 'tweak': t, m: l}

# Copyright 2021 Google LLC
#
# Use of this source code is governed by an MIT-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/MIT.
#
# Author: Nathan Huckleberry <nhuck@google.com>

from Crypto.Util.strxor import strxor

import aes
import cipher
import ctr
import polyval


class HCTR2(cipher.Blockcipher):
    def __init__(self):
        self._polyval = polyval.Polyval()

    def variant_name(self):
        return "{}_{}".format(self.name(),
                              self._block.variant_name())

    def _blockcipher_pairs(self):
        ciphers = []
        for kl in [16, 24, 32]:
            a = aes.AES()
            a.set_keylen(kl)
            c = ctr.XCTR()
            c.set_keylen(kl)
            ciphers.append((a, c))
        return ciphers

    def _lookup_block_pair(self, v):
        for (b, c) in self._blockcipher_pairs():
            if b.variant == v:
                return (b, c)
        raise Exception(f"Unknown block cipher: {v}")

    def variants(self):
        # tweak length in bytes
        for t in [0, 1, 2, 4, 8, 16, 32, 64, 128, 256]:
            for (bs, ctr) in self._blockcipher_pairs():
                yield {
                    'cipher': self.name(),
                    'blockcipher': bs.variant,
                    'lengths': {
                        'key': bs.variant['lengths']['key'],
                        'block': 16, # FIXME: blocksize, be consistent
                        'tweak': t
                    }}

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
        assert len(tweak) >= self.lengths()['tweak']
        hash_key = self._gen(key, 0)
        l = self._gen(key, 1)
        m = pt[0:16]
        n = pt[16:]
        mm = strxor(m, self._hash(hash_key, n, tweak))
        uu = self._block.encrypt(mm, key=key)
        s = strxor(strxor(mm, uu), l)
        # FIXME shouldn't be necessary to clip
        v = self._xctr.encrypt(n, key, s)[0:len(n)]
        u = strxor(uu, self._hash(hash_key, v, tweak))
        return u + v

    def decrypt(self, ct, key, tweak):
        assert len(key) == self.lengths()['key']
        assert len(ct) >= self.lengths()['block']
        assert len(tweak) >= self.lengths()['tweak']
        hash_key = self._gen(key, 0)
        l = self._gen(key, 1)
        u = ct[0:16]
        v = ct[16:]
        uu = strxor(u, self._hash(hash_key, v, tweak))
        mm = self._block.decrypt(uu, key=key)
        s = strxor(strxor(mm, uu), l)
        # FIXME shouldn't be necessary to clip
        n = self._xctr.encrypt(v, key, s)[0:len(v)]
        m = strxor(mm, self._hash(hash_key, n, tweak))
        return m + n

    def _setup_variant(self):
        self._block, self._xctr = self._lookup_block_pair(
            self.variant['blockcipher'])

    def test_input_lengths(self):
        v = dict(self.lengths())
        b = v['block']
        del v['block']
        for i in range(b * 10):
            for m in "plaintext", "ciphertext":
                yield {**v, m: b + i}

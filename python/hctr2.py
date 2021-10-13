# Copyright 2021 Google LLC
#
# Use of this source code is governed by an MIT-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/MIT.
#
# Author: Nathan Huckleberry <nhuck@google.com>

import Crypto.Util.strxor

import aes
import cipher
import ctr
import polyhash


class HCTR2(cipher.Blockcipher):
    def __init__(self):
        self._polyhash = polyhash.PolyHash()

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
                        'block': 16,
                        'tweak': t
                    }}

    def encrypt(self, pt, key, tweak):
        assert len(key) == self.lengths()['key']
        assert len(pt) >= self.lengths()['block']
        assert len(tweak) >= self.lengths()['tweak']
        block_key = key
        hash_key = self._block.encrypt(
            (0).to_bytes(
                self.lengths()['block'],
                byteorder='little'),
            key=block_key)
        l = self._block.encrypt(
            (1).to_bytes(
                self.lengths()['block'],
                byteorder='little'),
            key=block_key)
        m = pt[0:16]
        n = pt[16:]
        mm = Crypto.Util.strxor.strxor(
            m, self._polyhash.hash(
                hash_key, n, tweak))
        uu = self._block.encrypt(mm, key=block_key)
        s = Crypto.Util.strxor.strxor(Crypto.Util.strxor.strxor(mm, uu), l)
        v = self._xctr.encrypt(n, block_key, s)
        u = Crypto.Util.strxor.strxor(
            uu, self._polyhash.hash(
                hash_key, v, tweak))
        return (u + v)[0:len(pt)]

    def decrypt(self, ct, key, tweak):
        assert len(key) == self.lengths()['key']
        assert len(ct) >= self.lengths()['block']
        assert len(tweak) >= self.lengths()['tweak']
        block_key = key
        hash_key = self._block.encrypt(
            (0).to_bytes(
                self.lengths()['block'],
                byteorder='little'),
            key=block_key)
        l = self._block.encrypt(
            (1).to_bytes(
                self.lengths()['block'],
                byteorder='little'),
            key=block_key)
        u = ct[0:16]
        v = ct[16:]
        uu = Crypto.Util.strxor.strxor(
            u, self._polyhash.hash(
                hash_key, v, tweak))
        mm = self._block.decrypt(uu, key=block_key)
        s = Crypto.Util.strxor.strxor(Crypto.Util.strxor.strxor(mm, uu), l)
        n = self._xctr.decrypt(v, block_key, s)
        m = Crypto.Util.strxor.strxor(
            mm, self._polyhash.hash(
                hash_key, n, tweak))
        return (m + n)[0:len(ct)]

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

# Copyright 2021 Google LLC
#
# Use of this source code is governed by an MIT-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/MIT.

from Crypto.Util.strxor import strxor

import ciphers.aes
import ciphers.cipher
import ciphers.polyval
import ciphers.xctr


class HCTR2(ciphers.cipher.Bijection):
    def __init__(self):
        self._block = ciphers.aes.AES()
        self._polyval = ciphers.polyval.Polyval()
        self._xctr = ciphers.xctr.XCTR()

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

    def _schedule(self, key, i):
        b = i.to_bytes(self.lengths()['block'], byteorder='little')
        return self._block.encrypt(b, key=key)

    def encrypt(self, pt, key, tweak):
        blocksize = self.lengths()['block']
        assert len(key) == self.lengths()['key']
        assert len(pt) >= blocksize
        hash_key = self._schedule(key, 0)
        l = self._schedule(key, 1)
        m = pt[0:blocksize]
        n = pt[blocksize:]
        mm = strxor(m, self._hash(hash_key, n, tweak))
        uu = self._block.encrypt(mm, key=key)
        s = strxor(strxor(mm, uu), l)
        v = self._xctr.encrypt(n, nonce=s, key=key)
        u = strxor(uu, self._hash(hash_key, v, tweak))
        return u + v

    def decrypt(self, ct, key, tweak):
        blocksize = self.lengths()['block']
        assert len(key) == self.lengths()['key']
        assert len(ct) >= blocksize
        hash_key = self._schedule(key, 0)
        l = self._schedule(key, 1)
        u = ct[0:blocksize]
        v = ct[blocksize:]
        uu = strxor(u, self._hash(hash_key, v, tweak))
        mm = self._block.decrypt(uu, key=key)
        s = strxor(strxor(mm, uu), l)
        n = self._xctr.decrypt(v, nonce=s, key=key)
        m = strxor(mm, self._hash(hash_key, n, tweak))
        return m + n

    def test_input_lengths(self):
        v = dict(self.lengths())
        b = v['block']
        del v['block']
        lengths = {
            16: [16, 31, 128, 255],
            24: [17, 48, 512],
            32: [16, 17, 31, 48, 128, 255, 512]
        }
        for t in [0, 1, 16, 32, 47]:
            for l in lengths[v['key']]:
                for m in "plaintext", "ciphertext":
                    yield {**v, 'tweak': t, m: l}

    def testvec_fields(self):
        return ['key', 'tweak', 'plaintext', 'ciphertext']

    def convert_testvec(self, v):
        return {
            'key': v['input']['key'],
            'tweak': v['input']['tweak'],
            'plaintext': v['plaintext'],
            'ciphertext': v['ciphertext'],
        }

    _linux_tweak_len = 32

    def linux_convert_testvec(self, v):
        if len(v['input']['tweak']) != self._linux_tweak_len:
            return None
        return {
            'key': v['input']['key'],
            'iv': v['input']['tweak'],
            'ptext': v['plaintext'],
            'ctext': v['ciphertext'],
            'klen': len(v['input']['key']),
            'len': len(v['plaintext']),
            'description': None
        }

    def linux_name(self):
        return f"{self._block.name()}_{self.name()}"

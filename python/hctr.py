# Copyright 2021 Google LLC
#
# Use of this source code is governed by an MIT-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/MIT.

import Crypto.Util.strxor

import aes
import cipher
import ctr
import polyhash

class HCTR(cipher.Blockcipher):
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
      c = ctr.CTR()
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
              'key': 16 + bs.variant['lengths']['key'],
              'blocksize': 16,
              'tweak': t
          }}

  def encrypt(self, pt, key, tweak):
    assert len(key) == self.lengths()['key']
    assert len(pt) >= self.lengths()['blocksize']
    assert len(tweak) >= self.lengths()['tweak']
    hash_key = key[0:16]
    block_key = key[16:]
    m = pt[0:16]
    n = pt[16:]
    mm = Crypto.Util.strxor.strxor(m, self._polyhash.hash(hash_key, n + tweak))
    print(mm.hex())
    cc = self._block.encrypt(mm, key=block_key)
    print(cc.hex())
    s = Crypto.Util.strxor.strxor(mm, cc)
    d = self._ctr.encrypt(n, block_key, s)
    c = Crypto.Util.strxor.strxor(cc, self._polyhash.hash(hash_key, d + tweak))
    return (c + d)[0:len(pt)]

  def decrypt(self, ct, key, tweak):
    assert len(key) == self.lengths()['key']
    assert len(ct) >= self.lengths()['blocksize']
    assert len(tweak) >= self.lengths()['tweak']
    hash_key = key[0:16]
    block_key = key[16:]
    c = ct[0:16]
    d = ct[16:]
    cc = Crypto.Util.strxor.strxor(c, self._polyhash.hash(hash_key, d + tweak))
    mm = self._block.decrypt(cc, key=block_key)
    s = Crypto.Util.strxor.strxor(mm, cc)
    n = self._ctr.decrypt(d, block_key, s)
    m = Crypto.Util.strxor.strxor(mm, self._polyhash.hash(hash_key, n + tweak))
    return (m + n)[0:len(ct)]


  def _setup_variant(self):
    self._block, self._ctr = self._lookup_block_pair(self.variant['blockcipher'])

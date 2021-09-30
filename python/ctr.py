# Copyright 2021 Google LLC
#
# Use of this source code is governed by an MIT-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/MIT.
#
# Author: Nathan Huckleberry <nhuck@google.com>

import Crypto.Cipher.AES

import aes
import cipher

class Counter(object):
  def __init__(self, blocksize, nonce):
    self.nonce = nonce
    self.blocksize = blocksize
    self.reset()

  def counter(self):
    result = bytes(a ^ b for (a, b) in zip(self.nonce, self.current.to_bytes(self.blocksize, byteorder='little')))
    self.current += 1
    return result

  def reset(self):
    self.current = 1

class XCTR(cipher.Cipher):
  def set_keylen(self, k):
    self.choose_variant(lambda v: v["lengths"]["key"] == k)

  def variant_name(self):
    l = self.lengths()
    return "{}{}".format(self.name(), l['key'] * 8)

  def variants(self):
    for kl in [16, 24, 32]:
      yield {
          'cipher': 'AES-CTR',
          'lengths': {
              'block': 16,
              'key': kl
          }
      }

  def encrypt(self, pt, key, nonce):
    assert len(key) == self.lengths()['key']
    assert len(nonce) == self.lengths()['block']
    c = Counter(self.lengths()['block'], nonce)
    # TODO: Verify that the counter parameter is actually working
    a = Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_CTR, counter=c.counter)
    return a.encrypt(pt)

  def decrypt(self, ct, key, nonce):
    assert len(key) == self.lengths()['key']
    assert len(nonce) == self.lengths()['block']
    c = Counter(self.lengths()['block'], nonce)
    a = Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_CTR, counter=c.counter)
    return a.encrypt(ct)

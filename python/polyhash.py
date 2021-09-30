# Copyright 2021 Google LLC
#
# Use of this source code is governed by an MIT-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/MIT.
#
# Author: Nathan Huckleberry <nhuck@google.com>

import cipher
import gf

class Hash(cipher.Cipher):
    def __init__(self):
      self.gf = gf.GF(["X^128", "X^127", "X^126", "X^121", "X^0"])
      self.polyval_const = self.gf((1 << 127) | (1 << 124) | (1 << 121) | (1 << 114) | (1))

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

class PolyHash(Hash):
    def __init__(self):
        super().__init__()
        self.choose_variant(lambda v: v["lengths"]["key"] == 16)

    def variant_name(self):
        return self.name()

    def variants(self):
        yield {
            'cipher': 'PolyHash',
            'lengths': {
                'key': 16,
                'blocksize': 16,
                'output': 16,
            }
        }

    def pad(self, s):
        l = self.lengths()['blocksize']
        pad_len = ((l - (len(s) % l)) % l)
        return s + b'\x00'*pad_len

    def dot(self, x, y):
        return x * y * self.polyval_const

    def poly(self, m, key):
      assert len(m) % self.lengths()['blocksize'] == 0
      # Make h into a Galois field element
      h = self.gf(int.from_bytes(key, byteorder="little"))
      blocks = [m[i:i+self.lengths()['blocksize']] for i in range(0, len(m), self.lengths()['blocksize'])]
      hash_result = self.gf(0)
      for i in range(len(blocks)):
        exponent = (len(blocks) - 1) - i
        hash_result += self.dot((h**exponent), self.gf(int.from_bytes(blocks[i], byteorder='little')))
      return int(hash_result).to_bytes(self.lengths()['blocksize'], byteorder='little')

    def hash(self, key, message, tweak):
      assert len(key) == self.lengths()['key']
      blocks = b''
      if(len(message) % self.lengths()['blocksize'] == 0):
        blocks += (len(tweak)*8*2 + 2).to_bytes(self.lengths()['blocksize'], byteorder='little')
        blocks += self.pad(tweak)
        blocks += message
        blocks += b'\x00'*self.lengths()['blocksize']
      else:
        blocks += (len(tweak)*8*2 + 3).to_bytes(self.lengths()['blocksize'], byteorder='little')
        blocks += self.pad(tweak)
        blocks += self.pad(message + b'\x80')
        blocks += b'\x00'*self.lengths()['blocksize']
      return self.poly(blocks, key)

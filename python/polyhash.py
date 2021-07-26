# Copyright 2021 Google LLC
#
# Use of this source code is governed by an MIT-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/MIT.

import cipher
import gf

class Hash(cipher.Cipher):
    def __init__(self):
      self.gf = gf.GF(["X^128", "X^7", "X^2", "X^1", "X^0"])

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

    def hash(self, key, message):
      assert len(key) == self.lengths()['key']
      if(len(message) == 0):
        return key
      # Make h into a Galois field element
      h = self.gf(int.from_bytes(key, byteorder="big"))
      pad = ((16 - len(message)) % 16) % 16
      padded_message = message + b'\x00'*pad
      blocks = [padded_message[i:i+self.lengths()['blocksize']] for i in range(0, len(padded_message), self.lengths()['blocksize'])]
      # message length in bits used for length
      hash_result = self.gf(len(message) * 8) * h
      for i in range(len(blocks)):
        exponent = (len(blocks) + 1) - i
        hash_result += (h**exponent) * self.gf(int.from_bytes(blocks[i], byteorder='big'))
      return int(hash_result).to_bytes(self.lengths()['blocksize'], byteorder='big')

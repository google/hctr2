# Copyright 2021 Google LLC
#
# Use of this source code is governed by an MIT-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/MIT.

import cipher


class Hash(cipher.Cipher):
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


class Polyval(Hash):
    def __init__(self):
        super().__init__()
        self.choose_variant(lambda x: True)

    def variant_name(self):
        return self.name()

    def variants(self):
        yield {
            'cipher': 'Polyval',
            'lengths': {
                'key': 16,
                'blocksize': 16,
                'output': 16,
            }
        }

    def test_input_lengths(self):
        v = dict(self.lengths())
        del v["blocksize"]
        del v["output"]
        for mlen in range(0, 80, 16):
            yield {**v, "message": mlen}

    def hash(self, key, message):
        return bytes([0] * 16)
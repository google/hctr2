# Copyright 2018 Google LLC
#
# Use of this source code is governed by an MIT-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/MIT.

import copy


class Cipher(object):
    def copy(self): return copy.deepcopy(self)

    def name(self):
        return type(self).__name__

    @property
    def variant(self):
        return self._variant

    def _setup_variant(self):
        pass

    @variant.setter
    def variant(self, value):
        if value not in self.variants():
            raise Exception(f"Not a variant: {value}")
        self._variant = value
        self._setup_variant()

    def choose_variant(self, criterion):
        for v in self.variants():
            if criterion(v):
                self.variant = v
                return
        raise Exception("No variant matching criterion")

    def lengths(self):
        return self.variant["lengths"]

    def test_input_lengths(self):
        yield self.lengths()

    # External test vectors for this variant
    def external_testvectors(self, tvdir):
        if False:
            yield None

    def linux_name(self):
        return self.name()


class Bijection(Cipher):
    def make_testvector(self, input, description):
        input = input.copy()
        if "plaintext" in input:
            pt = input["plaintext"]
            del input["plaintext"]
            ct = self.encrypt(pt, **input)
        else:
            ct = input["ciphertext"]
            del input["ciphertext"]
            pt = self.decrypt(ct, **input)
        return {
            "cipher": self.variant,
            "description": description,
            "input": input,
            "plaintext": pt,
            "ciphertext": ct,
        }

    def check_testvector(self, tv):
        self.variant = tv["cipher"]
        assert tv["ciphertext"] == self.encrypt(tv["plaintext"], **tv["input"])
        assert tv["plaintext"] == self.decrypt(tv["ciphertext"], **tv["input"])

    def linux_testvec_struct(self):
        return 'cipher_testvec'


class Blockcipher(Bijection):
    def test_input_lengths(self):
        v = dict(self.lengths())
        b = v['block']
        del v['block']
        for m in "plaintext", "ciphertext":
            yield {**v, m: b}

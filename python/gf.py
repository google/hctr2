# Copyright 2021 Google LLC
#
# Use of this source code is governed by an MIT-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/MIT.
#
# Author: Nathan Huckleberry <nhuck@google.com>

class GF(object):
    def __init__(self, poly_terms):
        exponents = list(map(lambda x: int(x.replace("X^", "")), poly_terms))
        self.degree = max(exponents)
        assert self.degree % 8 == 0
        self.blocksize = self.degree // 8
        self.modulus = sum(list(map(lambda x: 1 << x, exponents)))

    class Element(object):
        def __init__(self, parent, value):
            self.parent = parent
            self.value = value

        def __add__(self, other):
            assert self.parent.modulus == other.parent.modulus
            return self.parent._add(self.value, other.value)

        def __mul__(self, other):
            assert self.parent.modulus == other.parent.modulus
            return self.parent._mul(self.value, other.value)

        def __pow__(self, other):
            assert isinstance(other, int)
            return self.parent._pow(self.value, other)

        # FIXME remove this
        def __int__(self):
            return self.value

        def to_bytes(self, *, byteorder):
            return self.parent._to_bytes(self.value, byteorder=byteorder)

    def from_bytes(self, b, *, byteorder):
        assert len(b) == self.blocksize
        return self.Element(self, int.from_bytes(b, byteorder=byteorder))

    # FIXME remove this
    def __call__(self, value):
        return self.Element(self, value)

    def _add(self, a, b):
        return self(a ^ b)

    def _mul(self, a, b):
        p = 0
        for i in range(self.degree):
            if((b & 1) == 1):
                p ^= a
            # Checks carry bit
            carry = ((1 << (self.degree - 1)) & a) != 0
            a <<= 1
            b >>= 1
            if(carry):
                a ^= self.modulus
        return self(p)

    # TODO: Exponent by square
    def _pow(self, a, e):
        r = self(1)
        for i in range(e):
            r = r * self(a)
        return r

    def _to_bytes(self, value, *, byteorder):
        return value.to_bytes(self.blocksize, byteorder=byteorder)

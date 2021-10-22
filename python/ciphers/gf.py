# Copyright 2021 Google LLC
#
# Use of this source code is governed by an MIT-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/MIT.

class GF(object):
    def __init__(self, exponents):
        self.degree = max(exponents)
        assert self.degree % 8 == 0
        self.blocksize = self.degree // 8
        self.modulus = sum(1 << x for x in exponents)

    class Element(object):
        def __init__(self, parent, value):
            self._parent = parent
            self._value = value

        def __add__(self, other):
            assert self._parent.modulus == other._parent.modulus
            return self._parent._add(self._value, other._value)

        def __mul__(self, other):
            assert self._parent.modulus == other._parent.modulus
            return self._parent._mul(self._value, other._value)

        def __pow__(self, exponent):
            assert isinstance(exponent, int)
            if exponent == 0:
                return self._parent.from_int(1)
            elif exponent == 1:
                return self
            else:
                res = self**(exponent >> 1)
                res *= res
                if exponent & 1:
                    res *= self
                return res

        def to_bytes(self, *, byteorder):
            return self._parent._to_bytes(self._value, byteorder=byteorder)

    def from_int(self, i):
        return self.Element(self, i)

    def from_bytes(self, b, *, byteorder):
        assert len(b) == self.blocksize
        return self.from_int(int.from_bytes(b, byteorder=byteorder))

    def _add(self, a, b):
        return self.from_int(a ^ b)

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
        return self.from_int(p)

    def _to_bytes(self, value, *, byteorder):
        return value.to_bytes(self.blocksize, byteorder=byteorder)

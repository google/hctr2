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
        self.modulus = sum(list(map(lambda x: 1 << x, exponents)))

    class Element(object):
        def __init__(self, parent, value):
            self.parent = parent
            self.value = value

        def __add__(self, other):
            assert self.parent.modulus == other.parent.modulus
            return self.parent.add(self.value, other.value)

        def __mul__(self, other):
            assert self.parent.modulus == other.parent.modulus
            return self.parent.mul(self.value, other.value)

        def __pow__(self, other):
            assert isinstance(other, int)
            return self.parent.pow(self.value, other)

        def __int__(self):
            return self.value

    def __call__(self, value):
        return self.Element(self, value)

    def mul(self, a, b):
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

    def add(self, a, b):
        return self(a ^ b)

    # TODO: Exponent by square
    def pow(self, a, e):
        r = self(1)
        for i in range(e):
            r = r * self(a)
        return r

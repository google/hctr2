# Copyright 2021 Google LLC
#
# Use of this source code is governed by an MIT-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/MIT.

from ciphers import hctr2, polyval, xctr

ciphers = [
    polyval.Polyval(),
    xctr.XCTR(),
    hctr2.HCTR2()
]


def lookup_cipher(name):
    for cipher in ciphers:
        if cipher.name().lower() == name.lower():
            return cipher
    raise Exception(f"No such cipher known: {name}")

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

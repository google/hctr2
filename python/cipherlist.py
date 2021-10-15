# Copyright 2021 Google LLC
#
# Use of this source code is governed by an MIT-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/MIT.

import hctr2
import polyval
import xctr

ciphers = [
    polyval.Polyval(),
    xctr.XCTR(),
    hctr2.HCTR2()
]

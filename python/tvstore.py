#!/usr/bin/env python3
#
# Copyright 2021 Google LLC
#
# Use of this source code is governed by an MIT-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/MIT.

import hexjson


class TvStore:
    def __init__(self, tvdir):
        self._storedir = tvdir / "ours"

    def _path(self, cipher):
        return self._storedir / cipher.name() / f"{cipher.variant_name()}.json"

    def write(self, cipher, tvs):
        hexjson.write_using_hex(self._path(cipher), tvs)

    def iter_read(self, cipher):
        yield from hexjson.iter_unhex(self._path(cipher))

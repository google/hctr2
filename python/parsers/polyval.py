# Copyright 2021 Google LLC
#
# Use of this source code is governed by an MIT-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/MIT.

def parse_tvs(tvdir):
    p = tvdir / "external" / "polyval.txt"
    with p.open() as f:
        d = None
        k = None
        v = None
        for l in f:
            l = l.strip()
            if l == "":
                if d:
                    d[k] = bytes.fromhex(v)
                    yield d
                    d = None
                    k = None
                    v = None
            elif "=" in l:
                if d is None:
                    d = {}
                else:
                    d[k] = bytes.fromhex(v)
                k, v = l.split("=", 2)
                k = k.strip()
                v = v.strip()
            else:
                v += l
        if d is not None:
            d[k] = bytes.fromhex(v)
            yield d

# Copyright 2021 Google LLC
#
# Use of this source code is governed by an MIT-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/MIT.

import hexjson
import paths
import polyval


def parse_tvs():
    p = paths.top / "test_vectors" / "other" / "polyval.txt"
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


def test_vectors(pv):
    for tv in parse_tvs():
        yield {
            'cipher': pv.variant,
            'description': "From RFC",
            'input': {
                'key': tv['Record authentication key'],
                'message': tv['POLYVAL input'],
            },
            'hash': tv['POLYVAL result'],
        }


def print_tvs():
    pv = polyval.Polyval()
    hexjson.dump_using_hex(test_vectors(pv))


if __name__ == "__main__":
    print_tvs()

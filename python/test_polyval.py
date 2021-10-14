# Copyright 2021 Google LLC
#
# Use of this source code is governed by an MIT-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/MIT.

import paths


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
                    d[k] = v
                    yield d
                    d = None
                    k = None
                    v = None
            elif "=" in l:
                if d is None:
                    d = {}
                else:
                    d[k] = v
                k, v = l.split("=", 2)
                k = k.strip()
                v = v.strip()
            else:
                v += l
        if d is not None:
            d[k] = v
            yield d


def print_tvs():
    for d in parse_tvs():
        for k, v in d.items():
            print(f"{k} = {v}")
        print()


if __name__ == "__main__":
    print_tvs()

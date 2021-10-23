# Copyright 2021 Google LLC
#
# Use of this source code is governed by an MIT-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/MIT.

import contextlib
import tvstore


def group_string(s, l):
    for i in range(0, len(s), l):
        yield s[i:i + l]


class TestvecFile:
    def __init__(self, f):
        self._f = f

    def write(self, *args):
        self._f.write(*args)

    def in_groups(self, prefix, separator, suffix, emptyval, convert, values):
        first = True
        for v in values:
            if first:
                self.write(prefix)
                first = False
            else:
                self.write(separator)
            convert(v)
        if first:
            self.write(emptyval)
        else:
            self.write(suffix)

    def as_c_string(self, b):
        hex = ''.join(f"\\x{a:02x}" for a in b)
        self.write(f'"{hex}"')

    def data_field(self, prefix, separator, suffix, emptyval, value):
        self.in_groups(prefix, separator, suffix, emptyval,
                       self.as_c_string, group_string(value, 8))

    def structs(self, struct, name, entries):
        self.write(f"\nconst struct {struct} {name}[] = {{\n")
        for vec in entries:
            self.write("\t{\n")
            for k, v in vec.items():
                self.write(f"\t\t.{k} = {{.len = {len(v)}, .data =")
                self.data_field('\n\t\t\t', '\n\t\t\t', '', ' ""', v)
                self.write('},\n')
            self.write("\t},\n")
        self.write(f"}};\n\n")
        self.write(f"const size_t {name}_count = ARRAY_SIZE({name});\n")

    def intro(self):
        self.write("/* GENERATED BY testvec_tool, DO NOT EDIT */\n\n")

    def include(self, include_file):
        self.write(f'#include "{include_file}.h"\n')


@contextlib.contextmanager
def make_tvfile(p):
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w") as f:
        tvf = TestvecFile(f)
        tvf.intro()
        yield tvf

def cipher_entries(args, cipher):
    tv_store = tvstore.TvStore(args.test_vectors)
    for v in cipher.variants():
        cipher.variant = v
        yield f'{cipher.variant_name().lower()}_tv', tv_store.iter_read(cipher)
    if any(True for s in cipher.external_testvectors(args.test_vectors)):
        yield (f'{cipher.name().lower()}_external_tv',
            cipher.external_testvectors(args.test_vectors))

def convert(args, cipher):
    targetdir = args.test_vectors / "converted" / "c"
    struct_name = f'{cipher.name().lower()}_testvec'
    basename = f"{cipher.name().lower()}_testvecs"
    target = targetdir / f"{basename}.c"
    entries = []
    with make_tvfile(target) as tvf:
        tvf.include(basename)
        for array_name, it in cipher_entries(args, cipher):
            print(f"Converting: {array_name}")
            tvf.structs(struct_name, array_name,
                (cipher.convert_testvec(s) for s in it))
            entries.append(array_name)
    target = targetdir / f"{basename}.h"
    with make_tvfile(target) as tvf:
        tvf.write('#pragma once\n\n')
        tvf.include('testvec')
        tvf.write('\n')
        tvf.write(f'struct {struct_name} {{\n')
        for field in cipher.testvec_fields():
            tvf.write(f'\tstruct testvec_buffer {field};\n')
        tvf.write(f'}};\n')
        for e in entries:
            tvf.write('\n')
            tvf.write(f'extern const struct {struct_name} {e}[];\n')
            tvf.write(f'extern const size_t {e}_count;\n')

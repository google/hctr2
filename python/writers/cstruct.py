# Copyright 2021 Google LLC
#
# Use of this source code is governed by an MIT-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/MIT.

import collections
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

    def write_linux_testvec_field(self, field_name, value):
        """Write a general field to a Linux crypto test vector."""
        if isinstance(value, bytes):
            self.write(f'\t\t.{field_name}\t=')
            self.data_field(' ', '\n\t\t\t  ', '', ' ""', value)
            self.write(',\n')
        else:
            self.write(f"\t\t.{field_name}\t= {value},\n")

    def write_linux_testvecs(self, struct, array_name, entries):
        self.write(f"static const struct {struct} {array_name}[] = {{\n")
        for vec in entries:
            if vec is not None:
                self.write('\t{\n')
                for k, v in vec.items():
                    self.write_linux_testvec_field(k, v)
                self.write('\t},\n')
        self.write('\n};\n\n')
        self.write(
            f"const size_t {array_name}_count = ARRAY_SIZE({array_name});\n")


@contextlib.contextmanager
def make_tvfile(p):
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w") as f:
        tvf = TestvecFile(f)
        tvf.intro()
        yield tvf


def testvectors(tvdir, cipher):
    yield from cipher.external_testvectors(tvdir)
    tv_store = tvstore.TvStore(tvdir)
    yield from tv_store.iter_read(cipher)


def cstruct_testvectors(tvdir, cipher):
    for s in testvectors(tvdir, cipher):
        yield cipher.convert_testvec(s)


def convert(tvdir, cipher):
    targetdir = tvdir / "converted" / "cstruct"
    struct_name = f'{cipher.name().lower()}_testvec'
    basename = f"{cipher.name().lower()}_testvecs"
    target = targetdir / f"{basename}.c"
    entries = []
    with make_tvfile(target) as tvf:
        tvf.include(basename)
        for v in cipher.variants():
            cipher.variant = v
            array_name = f'{cipher.variant_name().lower()}_tv'
            print(f"Converting: {array_name}")
            tvf.structs(struct_name, array_name,
                        cstruct_testvectors(tvdir, cipher))
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


def linux_testvectors(tvdir, cipher):
    length_count = collections.defaultdict(lambda: 0)
    max_count = 2
    for s in testvectors(tvdir, cipher):
        converted = cipher.linux_convert_testvec(s)
        if converted is None:
            continue
        lengths = sorted([(k, v)
                          for k, v in converted.items() if isinstance(v, int)])
        lengths = tuple(lengths)
        if length_count[lengths] < max_count:
            length_count[lengths] += 1
            yield converted


def convert_linux(tvdir, cipher):
    targetdir = tvdir / "converted" / "linux"
    struct_name = cipher.linux_testvec_struct()
    basename = f"{cipher.name().lower()}_testvecs"
    target = targetdir / f"{basename}.c"
    entries = []
    with make_tvfile(target) as tvf:
        tvf.include(basename)
        tvf.write('\n')
        for v in cipher.variants():
            cipher.variant = v
            array_name = f'{cipher.variant_name().lower()}_tv_template'
            print(f"Converting: {array_name}")
            tvf.write_linux_testvecs(struct_name, array_name,
                                     linux_testvectors(tvdir, cipher))
            entries.append(array_name)
    target = targetdir / f"{basename}.h"
    with make_tvfile(target) as tvf:
        tvf.write('#pragma once\n\n')
        tvf.include('testvec')
        for e in entries:
            tvf.write('\n')
            tvf.write(f'extern const struct {struct_name} {e}[];\n')
            tvf.write(f'extern const size_t {e}_count;\n')

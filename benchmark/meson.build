# Copyright 2018 Google LLC
#
# Use of this source code is governed by an MIT-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/MIT.

project('cipherbench', 'c',
        default_options: [
            'optimization=2',
            'warning_level=1'
        ])

conf_data = configuration_data()
conf_data.set10('SYMBOLS_HAVE_UNDERSCORE_PREFIX',
    meson.get_compiler('c').symbols_have_underscore_prefix())
configure_file(output : 'cbconfig.h', configuration : conf_data)
include_dirs = [
    include_directories('.'),
    include_directories('src'),
    include_directories('../test_vectors/converted/cstruct'),
    include_directories('../third_party/linux-kernel')
]
add_project_arguments('-Wno-pointer-sign', '-fno-strict-aliasing', '-fwrapv',
                      language : 'c')

src = [
    'src/aes.c',
    'src/cipherbench.c',
    'src/hctr2.c',
    'src/polyval.c',
    'src/xctr.c',
    'src/xts.c',
    '../third_party/linux-kernel/aes_ti.c',
    '../third_party/linux-kernel/gf128.c',
    '../test_vectors/converted/cstruct/hctr2_testvecs.c',
]

if host_machine.cpu_family() == 'aarch64'
    src += [
        'src/aarch64/polyval-ce-core.S',
        '../third_party/linux-kernel/aarch64/aes-ce.S',
    ]
endif
if host_machine.cpu_family() == 'x86_64'
    src += [
        'src/x86_64/polyval-clmulni_asm.S',
        '../third_party/linux-kernel/x86_64/aes_ctrby8_avx-x86_64.S',
        '../third_party/linux-kernel/x86_64/aesni-intel_asm.S',
    ]
endif
cipherbench = executable('cipherbench', src,
    include_directories : include_dirs)
benchmark('benchmark', cipherbench)
check4096 = custom_target('check4096',
    command: [cipherbench, '--bufsize=4096'],
    output: 'check4096', capture: true)
output4096 = custom_target('output4096',
    command: [cipherbench, '--bufsize=4096', '--ntries=25'],
    output: 'output4096', capture: true)
output512 = custom_target('output512',
    command: [cipherbench, '--bufsize=512', '--ntries=25'],
    output: 'output512', capture: true)

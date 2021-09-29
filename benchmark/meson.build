# Copyright 2018 Google LLC
#
# Use of this source code is governed by an MIT-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/MIT.

project('cipherbench', 'c')

conf_data = configuration_data()
conf_data.set10('KERNELISH', get_option('kernelish'))
conf_data.set10('SYMBOLS_HAVE_UNDERSCORE_PREFIX',
    meson.get_compiler('c').symbols_have_underscore_prefix())
configure_file(output : 'cbconfig.h', configuration : conf_data)
include_dirs = [
    include_directories('.'),
    include_directories('src'),
    include_directories('../third_party/linux-kernel')
]
add_project_arguments('-O2', '-Wall', '-Wno-pointer-sign', '-fno-strict-aliasing', language : 'c')

src = [
    'src/aes.c',
    'src/cipherbench.c',
    'src/hctr.c',
    'src/hctr-ctr.c',
    'src/hctr-polyhash.c',
    'src/insn_timing.c',
    '../third_party/linux-kernel/aes_ti.c',
    '../third_party/linux-kernel/gf128.c',
]

if host_machine.cpu_family() == 'aarch64'
    src += [
        '../third_party/linux-kernel/aarch64/aes-ce.S',
        '../third_party/linux-kernel/aarch64/hctr-polyhash-pmull_asm.S',
    ]
endif
if host_machine.cpu_family() == 'x86_64'
    src += [
	    'src/x86_64/hctr-polyhash-clmulni_asm.S',
        '../third_party/linux-kernel/x86_64/aes_xctr.S',
        '../third_party/linux-kernel/x86_64/aesni-intel_asm.S',
    ]
endif
cipherbench = executable('cipherbench', src,
    include_directories : include_dirs)
benchmark('benchmark', cipherbench)
ciphers = ['HCTR', 'HCTR-Polyhash', 'HCTR-CTR']
check4096 = custom_target('check4096',
    command: [cipherbench, '--bufsize=4096'] + ciphers,
    output: 'check4096', capture: 'true')
output4096 = custom_target('output4096',
    command: [cipherbench, '--bufsize=4096', '--ntries=25'] + ciphers,
    output: 'output4096', capture: 'true')
output512 = custom_target('output512',
    command: [cipherbench, '--bufsize=512', '--ntries=25'] + ciphers,
    output: 'output512', capture: 'true')

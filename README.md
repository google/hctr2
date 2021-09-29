# HCTR2

HCTR2 is a wide-block encryption mode that supports hardware acceleration. It is
efficient on processors that support accelerated AES instructions and carry-less
multiplication instructions (CLMUL/PMULL).

HCTR2 is a super pseudorandom permuation, meaning it works on an arbitrary
length block size, allowing arbitrary length plaintexts to be a single block.
This means that any change to the plaintext will produce an unrecognizably
different ciphertext.

## File layout

 * `benchmark/`: HCTR implementation in C and benchmarking code
 * `python/`: HCTR implementation in Python
 * `third_party`: derived works covered by a different licesnse than our main MIT license

## Notices

`third_party/` includes derived works not covered by the MIT license;
specifically software derived from the Linux kernel and licensed under GPLv2.

We include here a variety of algorithms and implementations; we make no
guarantee they are suitable for production use.

This is not an officially supported Google product.

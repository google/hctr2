# HCTR2

HCTR2 is an efficient wide-block encryption mode that supports hardware
acceleration. It is intended for use on processors that support accelerated
AES and carry-less multiplication (CLMUL/PMULL).

When encrypting filenames, IV reuse is common to allow efficient directory
lookups. With traditional filename encryption algorithms like AES-CTS-CBC, two
filenames that share a prefix of the algorithm's blocksize will have ciphertexts
that also share a prefix.  This leaks more information to an attacker than
necessary. HCTR2 is an efficient construction that eliminated the shared prefix
issue. HCTR2 is a super pseudorandom permuation, meaning it works on an
arbitrary length block size, allowing the entire filename to be a single block.
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

# HCTR2

HCTR2 is a wide-block encryption mode that is efficient on processors with
instructions to accelerate AES and carryless multiplication, e.g. x86 processors
with AES-NI and CLMUL, and ARM processors with the ARMv8 Crypto Extensions.

HCTR2 is intended for applications such as disk encryption that require
length-preserving encryption, so authenticated algorithms such as AES-GCM cannot
be used.  Usually AES-XTS is used in such cases, but XTS has the disadvantage
that it is a "narrow-block mode": a 1-bit change to the plaintext changes only
16 bytes of ciphertext and vice versa, revealing more information to the
attacker than necessary.  HCTR2 is a wide-block mode ("super-pseudorandom
permutation"), so any change to the plaintext will result in an unrecognizably
different ciphertext and vice versa.

For more information, see the HCTR2 paper.

## File layout

 * `paper/`: LaTeX sources for our paper presenting HCTR2
 * `test_vectors/other/`: Test vectors we use to validate our implementations
    of other primitives
 * `test_vectors/ours/`: Test vectors we generate, in JSON format
 * `python/`: Python implementation and test vector generation
 * `benchmark/`: C implementation and benchmarking code
 * `third_party/`: derived works covered by a different license than our main
   MIT license

## Notices

`third_party/` includes derived works not covered by the MIT license;
specifically software derived from the Linux kernel and licensed under GPLv2.

We include here a variety of algorithms and implementations; we make no
guarantee they are suitable for production use.

This is not an officially supported Google product.

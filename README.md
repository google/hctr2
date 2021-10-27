# HCTR2

HCTR2 is a length-preserving encryption mode that is efficient on processors with
instructions to accelerate AES and carryless multiplication, e.g. x86 processors
with AES-NI and CLMUL, and ARM processors with the ARMv8 Crypto Extensions.

Usually, the right mode to use for encryption is a mode like AES-GCM or
AES-GCM-SIV which includes a tag as well as a fresh nonce. However there
are some applications, such as disk encryption, where the ciphertext
must be the same size as the plaintext and there is no room for such
information. For disk encryption, AES-XTS is often used, but it operates
on each block of the plaintext independently, so changes to a given
plaintext block affect only the corresponding ciphertext block
and vice versa, revealing more information to the attacker than necessary.
HCTR2 is a tweakable super-pseudorandom permutation: any change to the
plaintext will result in an unrecognizably different ciphertext
and vice versa.

For more information, see the [HCTR2 paper](https://ia.cr/2021/1441).

## File layout

 * [`paper/`](paper/): LaTeX sources for our paper presenting HCTR2
 * [`test_vectors/other/`](test_vectors/other/): 
    Test vectors we use to validate our implementations
    of other primitives
 * [`test_vectors/ours/`](test_vectors/ours/):
    Test vectors we generate, in JSON format
 * [`python/`](python/):
    Python implementation and test vector generation
 * [`benchmark/`](benchmark/):
    C implementation and benchmarking code
 * [`third_party/`](third_party/):
    derived works covered by a different license than our main
    MIT license

## Notices

`third_party/` includes derived works not covered by the MIT license;
specifically software derived from the Linux kernel and licensed under GPLv2.

We include here a variety of algorithms and implementations; we make no
guarantee they are suitable for production use.

This is not an officially supported Google product.

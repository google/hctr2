from ctr import *
from hctr import *
from polyhash import *
import os

c = CTR()
c.set_keylen(16)
x = os.urandom(16)
k = os.urandom(16)
ct = c.encrypt("abc123", k, x)
print(ct)
pt = c.decrypt(ct, k, x)
print(pt)

p = PolyHash()
h = os.urandom(16)
print(p.hash(h, b'abc123'))

hctr = HCTR()
print(list(hctr.variants()))
hctr.choose_variant(lambda v: v['blockcipher']['lengths']['key'] == 32)
k = os.urandom(hctr.lengths()['key'])
txt = b'a'*30
tweak = b'\x05'
ct = hctr.encrypt(txt, k, tweak)
print(ct)
pt = hctr.decrypt(ct, k, tweak)
print(pt)
tweak = b'\x06'
ct = hctr.encrypt(txt, k, tweak)
print(ct)
pt = hctr.decrypt(ct, k, tweak)
print(pt)

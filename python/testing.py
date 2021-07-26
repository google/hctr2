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
hctr.choose_variant(lambda v: v['blockcipher']['lengths']['key'] == 32 and v['lengths']['tweak'] == 1)
k = os.urandom(hctr.lengths()['key'])

ct = hctr.encrypt(b'a'*30, k, b'\x05')
print(ct)
pt = hctr.decrypt(ct, k, b'\x05')
print(pt)
ct = hctr.encrypt(b'a'*25+b'b'+b'a'*4, k, b'\x05')
print(ct)
pt = hctr.decrypt(ct, k, b'\x05')
print(pt)

ct = hctr.encrypt(b'a'*30, k, b'\x06')
print(ct)
pt = hctr.decrypt(ct, k, b'\x06')
print(pt)
ct = hctr.encrypt(b'a'*25+b'b'+b'a'*4, k, b'\x06')
print(ct)
pt = hctr.decrypt(ct, k, b'\x06')
print(pt)

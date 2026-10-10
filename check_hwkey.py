#!/usr/bin/env python3
"""Check which host identity (product name + serial) the sensor's TLS key blob
was paired with. Read-only, offline: it only uses tls_flash.bin, never touches USB.
Usage: python3 check_hwkey.py "<product name>" "<serial>"
Linux values: /sys/class/dmi/id/product_name and product_serial
Windows: wmic csproduct get name,identifyingnumber
(Constants and formulas are copied from python-validity/validitysensor/tls.py)"""
import hmac, struct, sys
from hashlib import sha256
from binascii import unhexlify

password_hardcoded = unhexlify('717cd72d0962bc4a2846138dbb2c24192512a76407065f383846139d4bec2033')
gwk_sign_hardcoded = unhexlify('3a4c76b76a97981d1274247e166610e77f4d9c9d07d3c728e532916bdd28b454')

def prf(secret, seed, length):
    n = (length + 31) // 32
    res = b''
    a = hmac.new(secret, seed, sha256).digest()
    while n > 0:
        res += hmac.new(secret, a + seed, sha256).digest()
        a = hmac.new(secret, a, sha256).digest()
        n -= 1
    return res[:length]

def main():
    name, serial = sys.argv[1], sys.argv[2]
    fl = open('tls_flash.bin', 'rb').read()
    p, blocks = 0, {}
    while p < len(fl):
        bid, bsz = struct.unpack('<HH', fl[p:p+4]); p += 36
        if bid == 0xffff: break
        blocks[bid] = fl[p:p+bsz]; p += bsz
    blob = blocks[4]
    body = blob[1:]
    c, mac = body[:-0x20], body[-0x20:]
    hw_key = name.encode('ascii') + b'\0' + serial.encode('ascii') + b'\0'
    enc = prf(password_hardcoded, b'GWK' + hw_key, 0x20)
    val = prf(enc, b'GWK_SIGN' + gwk_sign_hardcoded, 0x20)
    ok = hmac.new(val, c, sha256).digest() == mac
    print('MATCH: key blob was paired with this identity' if ok else 'no match')

main()

#!/usr/bin/env python3.4

import binascii
import hashlib
import hmac
import struct
import ecdsa
import ed25519
from base58 import b58encode_check

privdev = 0x80000000

def int_to_string(x, pad):
    result = [b'\x00'] * pad
    while x > 0:
        pad -= 1
        ordinal = x & 0xFF
        result[pad] = (bytes([ordinal]))
        x >>= 8
    return b''.join(result)

def string_to_int(s):
    result = 0
    for c in s:
        result = (result << 8) + c
    return result

# mode 0 - compatible with BIP32 private derivation
def seed2hdnode(seed, modifier, curve):
    k = seed
    while True:
        h = hmac.new(modifier, seed, hashlib.sha512).digest()
        key, chaincode = h[:32], h[32:]
        a = string_to_int(key)
        if (curve == 'ed25519'):
            break
        if (a < curve.order and a != 0):
            break
        seed = h

    return (key, chaincode)

def fingerprint(publickey):
    h = hashlib.new('ripemd160', hashlib.sha256(publickey).digest()).digest()
    return h[:4]

def b58xprv(parent_fingerprint, private_key, chain, depth, childnr):
    raw = (b'\x04\x88\xad\xe4' +
              bytes([depth]) + parent_fingerprint + int_to_string(childnr, 4) +
              chain + b'\x00' + private_key)
    return b58encode_check(raw)

def b58xpub(parent_fingerprint, public_key, chain, depth, childnr):
    raw = (b'\x04\x88\xb2\x1e' +
              bytes([depth]) + parent_fingerprint + int_to_string(childnr, 4) +
              chain + public_key)
    return b58encode_check(raw)

def publickey(private_key, curve):
    if curve == 'ed25519':
        sk = ed25519.SigningKey(private_key)
        return b'\x00' + sk.get_verifying_key().to_bytes()
    else:
        Q = string_to_int(private_key) * curve.generator
        xstr = int_to_string(Q.x(), 32)
        parity = Q.y() & 1
        return bytes([2 + parity]) + xstr

def derive(parent_key, parent_chaincode, i, curve):
    assert len(parent_key) == 32
    assert len(parent_chaincode) == 32
    k = parent_chaincode
    if ((i & privdev) != 0):
        key = b'\x00' + parent_key
    else:
        key = publickey(parent_key, curve)
    d = key + struct.pack('>L', i)
    while True:
        h = hmac.new(k, d, hashlib.sha512).digest()
        key, chaincode = h[:32], h[32:]
        if curve == 'ed25519':
            break
        a = string_to_int(key)
        key = (a + string_to_int(parent_key)) % curve.order
        if (a < curve.order and key != 0):
            key = int_to_string(key, 32)
            break
        d = b'\x01' + h[32:] + struct.pack('>L', i)

    return (key, chaincode)

def get_curve_info(curvename):
    if curvename == 'secp256k1':
        return (ecdsa.curves.SECP256k1, b'Bitcoin seed') 
    if curvename == 'nist256p1':
        return (ecdsa.curves.NIST256p, b'Nist256p1 seed') 
    if curvename == 'ed25519':
        return ('ed25519', b'ed25519 seed')
    raise BaseException('unsupported curve: '+curvename)

def show_testvector(name, curvename, seedhex, derivationpath):
    curve, seedmodifier = get_curve_info(curvename)
    master_seed = binascii.unhexlify(seedhex)
    k,c = seed2hdnode(master_seed, seedmodifier, curve)
    p = publickey(k, curve)
    fpr = b'\x00\x00\x00\x00'
    path = 'm'
    print("### "+name+" for "+curvename)
    print('')
    print("Seed (hex): " + seedhex)
    print('')
    print('* Chain ' + path)
    print('  * fingerprint: ' + binascii.hexlify(fpr).decode())
    print('  * chain code: ' + binascii.hexlify(c).decode())
    print('  * private: ' + binascii.hexlify(k).decode())
    print('  * public: ' + binascii.hexlify(p).decode())
    depth = 0
    for i in derivationpath:
        if curve == 'ed25519':
            # no public derivation for ed25519
            i = i | privdev
        fpr = fingerprint(p)
        depth = depth + 1
        path = path + "/" + str(i & (privdev-1))
        if ((i & privdev) != 0):
            path = path + "<sub>H</sub>"
        k,c = derive(k, c, i, curve)
        p = publickey(k, curve) 
        print('* Chain ' + path)
        print('  * fingerprint: ' + binascii.hexlify(fpr).decode())
        print('  * chain code: ' + binascii.hexlify(c).decode())
        print('  * private: ' + binascii.hexlify(k).decode())
        print('  * public: ' + binascii.hexlify(p).decode())
    public = binascii.hexlify(p).decode()
    return public

def show_testvectors(name, curvenames, seedhex, derivationpath):
    for curvename in curvenames:
        public = show_testvector(name, curvename, seedhex, derivationpath)
    return public

if __name__ == "__main__":
    """curvenames = ['secp256k1', 'nist256p1', 'ed25519']
    show_testvectors("Test vector 1", curvenames,
                    '000102030405060708090a0b0c0d0e0f',
                    [privdev + 0, 1, privdev + 2, 2, 1000000000])
    show_testvectors("Test vector 2", curvenames,
                    'fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542',
                    [0, privdev + 2147483647, 1, privdev + 2147483646, 2])
    show_testvectors("Test derivation retry", ['nist256p1'],
                    '000102030405060708090a0b0c0d0e0f',
                    [privdev + 28578, 33941])
    show_testvectors("Test seed retry", ['nist256p1'],
                    'a7305bc8df8d0951f0cb224c0e95d7707cbdf2c6ce7e8d481fec69c7ff5e9446',
                    [])"""
    
    Bip32KeyIndex_HardenIndex_44 = 0x8000002c
    Bip32KeyIndex_HardenIndex_9000 = 0x80002328
    Bip32KeyIndex_HardenIndex_0 = 0x80000000
    Bip32KeyIndex_0 = 0x00000000
    
    public = show_testvectors("Test vector", ['secp256k1'],
                    '23cd8f21118749c3d348e114a53b1cede7fd020bfa5f9bf67938b12d67b522aaf370480ed670a1c41aae0c0062faceb6aea0c031cc2907e8aaadd23ae8076818',
                    [
                        Bip32KeyIndex_HardenIndex_44,
                        Bip32KeyIndex_HardenIndex_9000,
                        Bip32KeyIndex_HardenIndex_0,
                        Bip32KeyIndex_0,
                        Bip32KeyIndex_0
                    ])

print('\npublic:', public)

import hashlib
from Crypto.Hash import RIPEMD160
from bip_utils import Bech32Encoder

# Assuming Bech32Encoder is already imported or implemented

def child_to_avaxp_address(public_key) -> str:
    # raw_compressed_key_hex = public_key
    raw_compressed_key_hex = '025382fd923485ccbf2aea4f4dbe164124aea708f3977286b1f65ff0e1ef0fe939'
    raw_compressed_key_bytes = bytes.fromhex(raw_compressed_key_hex)
    
    # SHA-256 Hashing
    m = hashlib.sha256()
    m.update(raw_compressed_key_bytes)
    
    # RIPEMD160 Hashing
    n = RIPEMD160.new()
    n.update(m.digest())
    
    # Bech32 Encoding
    b32_encoded = Bech32Encoder().Encode('avax', n.digest())
    
    # return f'P-{b32_encoded}'
    return 'P-{}'.format(b32_encoded)


# Test the function
print(child_to_avaxp_address(public))
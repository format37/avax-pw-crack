from bip_utils import Bip32Slip10Secp256k1, Bech32Encoder, Bip32KeyIndex
import hashlib
from Crypto.Hash import RIPEMD160

import inspect
import abc

print(inspect.getfile(abc))

def child_to_avaxp_address(child) -> str:
    # Step 4: Public Key Generation
    # 4.1 Generate Public Key: Generate the compressed public key from the child private key.
    
    # Step 5: SHA-256 Hashing
    # 5.1 Initialize SHA-256: Initialize a SHA-256 hash object.
    m = hashlib.sha256()
    # 5.2 Update SHA-256 State: Feed the compressed public key bytes into the SHA-256 hash object.
    # 5.3 Finalize SHA-256: Obtain the SHA-256 hash.    
    m.update(child.PublicKey().RawCompressed().ToBytes())
    print('m.digest():', m.digest())   
    
    # Step 6: RIPEMD-160 Hashing
    # 6.1 Initialize RIPEMD-160: Initialize a RIPEMD-160 hash object.
    # 6.2 Update RIPEMD-160 State: Feed the SHA-256 hash into the RIPEMD-160 hash object.
    # 6.3 Finalize RIPEMD-160: Obtain the RIPEMD-160 hash.
    n = RIPEMD160.new()    
    n.update(m.digest())
    print('n.digest():', n.digest())
    
    # Step 7: Bech32 Encoding
    # 7.1 Bech32 Encode: Use a Bech32 encoding function to encode the RIPEMD-160 hash with the prefix 'avax'.
    b32_encoded = Bech32Encoder().Encode('avax', n.digest())
    
    # Step 8: Final Address
    # 8.1 Concatenate: Prepend 'P-' to the Bech32 encoded string to get the final Avalanche address.
    return f'P-{b32_encoded}'


# Step 1: Seed Generation
# 1.1 Initialize Seed: Manually initialize the seed from the hexadecimal string.
hex_result = '23cd8f21118749c3d348e114a53b1cede7fd020bfa5f9bf67938b12d67b522aaf370480ed670a1c41aae0c0062faceb6aea0c031cc2907e8aaadd23ae8076818'
seed_bytes_restored = bytes.fromhex(hex_result)

# import pkg_resources
# distribution = pkg_resources.get_distribution("abc")
# print('LIBRARY location:', distribution.location)

# priv_key_bytes, chain_code_bytes = seed_bytes_restored._MasterKeyGenerator().GenerateFromSeed(seed_bytes_restored)
# print('>>> FromSeed: priv_key_bytes as hex', priv_key_bytes.hex())
# print('>>> FromSeed: chain_code_bytes as hex', chain_code_bytes.hex())


# Step 2: Master Key Generation (Bip32Slip10Secp256k1)
# 2.1 Generate Master Key: Use the seed to generate the master private key and chain code.
# /mnt/hdd0/alex/anaconda3/lib/python3.11/site-packages/bip_utils/bip/bip32/base/bip32_base.py
master = Bip32Slip10Secp256k1.FromSeed(seed_bytes_restored)
print('master', master)

# Step 3: Child Key Derivation
# 3.1 Child Key Derivation Function: Implement or use an existing function to derive child keys.
# 3.2 Derive Child Keys: Derive the child keys `m/44'/9000'/0'/0` from the master key.
# m/44'/9000'/0'
child = (master
            .ChildKey(Bip32KeyIndex.HardenIndex(44))
            .ChildKey(Bip32KeyIndex.HardenIndex(9000))
            .ChildKey(Bip32KeyIndex.HardenIndex(0))
            .ChildKey(0))
child_key = child.ChildKey(0)
# print('child_key', child_key)
# print('PublicKey:', child.PublicKey())
# print('child_key.PublicKey().RawUncompressed():', child_key.PublicKey().RawUncompressed())
# print('RawCompressed:', child.PublicKey().RawCompressed())

# print('base_child', child_to_avaxp_address(child_key))

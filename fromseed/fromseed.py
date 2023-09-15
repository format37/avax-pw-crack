from bip_utils import Bip32Slip10Secp256k1, Bech32Encoder, Bip32KeyIndex
import hashlib
from Crypto.Hash import RIPEMD160

def child_to_avaxp_address(child) -> str:
    m = hashlib.sha256()
    print('PublicKey:', child.PublicKey())
    print('RawCompressed:', child.PublicKey().RawCompressed())
    print('ToBytes:', child.PublicKey().RawCompressed().ToBytes())
    m.update(child.PublicKey().RawCompressed().ToBytes())
    print('m.digest():', m.digest())
    
    n = RIPEMD160.new()
    n.update(m.digest())
    print('n.digest():', n.digest())
    
    b32_encoded = Bech32Encoder().Encode('avax', n.digest())
    return f'P-{b32_encoded}'

hex_result = '23cd8f21118749c3d348e114a53b1cede7fd020bfa5f9bf67938b12d67b522aaf370480ed670a1c41aae0c0062faceb6aea0c031cc2907e8aaadd23ae8076818'
seed_bytes_restored = bytes.fromhex(hex_result)
master = Bip32Slip10Secp256k1.FromSeed(seed_bytes_restored)
print('master', master)
# m/44'/9000'/0'
child = (master
            .ChildKey(Bip32KeyIndex.HardenIndex(44))
            .ChildKey(Bip32KeyIndex.HardenIndex(9000))
            .ChildKey(Bip32KeyIndex.HardenIndex(0))
            .ChildKey(0))
child_key = child.ChildKey(0)
print('child_key', child_key)
print('base_child', child_to_avaxp_address(child_key))

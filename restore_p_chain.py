import hashlib
from bip_utils import (
    Bip39SeedGenerator, Bip32Slip10Secp256k1, Bip32KeyIndex, Bech32Encoder
)
from Crypto.Hash import RIPEMD160

def restore_p_chain_address(mnemonic, passphrase):
    # Generate seed from mnemonic and passphrase
    seed_bytes = Bip39SeedGenerator(mnemonic).Generate(passphrase)
    # Print as hex
    print('Seed:', seed_bytes.hex())
    
    # Create master key
    master_key = Bip32Slip10Secp256k1.FromSeed(seed_bytes)
    # Print as hex
    print('Master key:', master_key)
    # Print master key -> chain code
    print('Master key -> chain code:', master_key.ChainCode().ToHex())
    # Print Master key -> private key
    print('Master key -> private key:', master_key.PrivateKey().Raw().ToHex())
    print('\n')
    # # Derive the Avalanche P-chain path: m/44'/9000'/0'/0/0
    # child_key = (master_key
    #              .ChildKey(Bip32KeyIndex.HardenIndex(44))
    #              .ChildKey(Bip32KeyIndex.HardenIndex(9000))
    #              .ChildKey(Bip32KeyIndex.HardenIndex(0))
    #              .ChildKey(0)
    #              .ChildKey(0))
    
    child_key = (master_key.ChildKey(Bip32KeyIndex.HardenIndex(44)))
    print('Child key -> chain code:', child_key.ChainCode().ToHex())
    print('Child key -> private key:', child_key.PrivateKey().Raw().ToHex())
    print('Child key -> public key:', child_key.PublicKey().RawCompressed().ToHex())
    print('\n')

    child_key = (child_key.ChildKey(Bip32KeyIndex.HardenIndex(9000)))
    print('Child key -> chain code:', child_key.ChainCode().ToHex())
    print('Child key -> private key:', child_key.PrivateKey().Raw().ToHex())
    print('Child key -> public key:', child_key.PublicKey().RawCompressed().ToHex())
    print('\n')

    child_key = (child_key.ChildKey(Bip32KeyIndex.HardenIndex(0)))
    print('Child key -> chain code:', child_key.ChainCode().ToHex())
    print('Child key -> private key:', child_key.PrivateKey().Raw().ToHex())
    print('Child key -> public key:', child_key.PublicKey().RawCompressed().ToHex())
    print('\n')

    child_key = (child_key.ChildKey(0))
    print('Child key -> chain code:', child_key.ChainCode().ToHex())
    print('Child key -> private key:', child_key.PrivateKey().Raw().ToHex())
    print('Child key -> public key:', child_key.PublicKey().RawCompressed().ToHex())
    print('\n')

    child_key = (child_key.ChildKey(0))
    print('Child key -> chain code:', child_key.ChainCode().ToHex())
    print('Child key -> private key:', child_key.PrivateKey().Raw().ToHex())
    print('Child key -> public key:', child_key.PublicKey().RawCompressed().ToHex())
    print('\n')

    # exit()
    
    # Get public key
    public_key = child_key.PublicKey().RawCompressed().ToBytes()
    print('Public key:', public_key.hex())
    
    # Perform SHA256 hash
    sha256_hash = hashlib.sha256(public_key).digest()
    print('SHA256 hash:', sha256_hash.hex())
    
    # Perform RIPEMD160 hash
    ripemd160_hash = RIPEMD160.new(sha256_hash).digest()
    print('RIPEMD160 hash:', ripemd160_hash.hex())
    
    # Encode with Bech32
    bech32_address = Bech32Encoder().Encode('avax', ripemd160_hash)
    print('Bech32 address:', bech32_address)
    
    # Return the P-chain address
    return f'P-{bech32_address}'

# Example usage
mnemonic = "sell stereo useless course suffer tribe jazz monster fresh excess wire again father film sudden pelican always room attack rubber pelican trash alone cancel"
passphrase = "TESTPHRASE"

p_chain_address = restore_p_chain_address(mnemonic, passphrase)
print(f"Your restored P-chain address: {p_chain_address}")
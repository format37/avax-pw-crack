import sys
import os

import hashlib
from bip_utils import (
    Bip39SeedGenerator, Bip32Slip10Secp256k1, Bip32KeyIndex, Bech32Encoder
)
from Crypto.Hash import RIPEMD160

def word_to_id(s):
    alphabet = 'abcdefghijklmnopqrstuvwxyz'
    base = len(alphabet)
    result = 0
    
    for char in s:
        result = result * base + alphabet.index(char) + 1
    
    return result

def id_to_word(n):
    alphabet = 'abcdefghijklmnopqrstuvwxyz'
    base = len(alphabet)
    result = []
    
    while n > 0:
        n -= 1  # Adjust for 0-based indexing
        result.append(alphabet[n % base])
        n //= base
    
    return ''.join(reversed(result))

def restore_p_chain_address(mnemonic, passphrase):
    # Generate seed from mnemonic and passphrase
    seed_bytes = Bip39SeedGenerator(mnemonic).Generate(passphrase)    
    
    # Create master key
    master_key = Bip32Slip10Secp256k1.FromSeed(seed_bytes)   
    index = 44
    child_key = (master_key.ChildKey(Bip32KeyIndex.HardenIndex(index)))
    index = 9000
    child_key = (child_key.ChildKey(Bip32KeyIndex.HardenIndex(index)))
    index = 0
    child_key = (child_key.ChildKey(Bip32KeyIndex.HardenIndex(index)))
    index = 0
    child_key = (child_key.ChildKey(index))
    index = 0
    child_key = (child_key.ChildKey(index))
    
    # Get public key
    public_key = child_key.PublicKey().RawCompressed().ToBytes()
    
    # Perform SHA256 hash
    sha256_hash = hashlib.sha256(public_key).digest()
    
    # Perform RIPEMD160 hash
    ripemd160_hash = RIPEMD160.new(sha256_hash).digest()
    
    # Encode with Bech32
    bech32_address = Bech32Encoder().Encode('avax', ripemd160_hash)
    
    # Return the P-chain address
    return f'P-{bech32_address}'


def main():
    mnemonic = "sell stereo useless course suffer tribe jazz monster fresh excess wire again father film sudden pelican always room attack rubber pelican trash alone cancel"

    word = "dx" # 128

    identifier = word_to_id(word)
    print(f"The variant ID corresponding to '{word}' is: {identifier}")

    variant_id = 128 # dx
    variant_id = 480001
    word = id_to_word(variant_id)
    print(f"The letter variant corresponding to {variant_id} is: {word}")

    p_chain_address = restore_p_chain_address(mnemonic, word) # P-avax10mr7jsu2x87p5dfmrslrl2fjz6gau2hcncmqer

    print(f"P-chain address: {p_chain_address}")


if __name__ == "__main__":
    main()

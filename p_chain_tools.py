import sys
import os
import json

import hashlib
from bip_utils import (
    Bip39SeedGenerator, Bip32Slip10Secp256k1, Bip32KeyIndex, Bech32Encoder
)
from Crypto.Hash import RIPEMD160

def _sum_of_variants_up_to_length(length: int, alphabet_size: int) -> int:
    """
    Returns the total count of variants from length=1 up to length=length
    for an alphabet of given size.
    """
    return sum(alphabet_size**i for i in range(1, length + 1))

def word_to_id(alphabet: str, word: str) -> int:
    """
    Returns the 1-based index of the given word among all possible variants
    that start at length=1, using the provided alphabet.
    """
    word_length = len(word)
    alphabet_size = len(alphabet)
    
    # Add up all variants that have length less than current word length
    offset = _sum_of_variants_up_to_length(word_length - 1, alphabet_size)
    
    # Compute word's rank among words of its length
    rank = 0
    for char in word:
        char_value = alphabet.index(char)
        rank = rank * alphabet_size + char_value
    
    return offset + rank + 1

def id_to_word(alphabet: str, index: int) -> str:
    """
    Returns the word corresponding to the 0-based index among all possible variants,
    using the provided alphabet.
    """
    if index == 0:
        return alphabet[0]  # Return first character for index 0
        
    alphabet_size = len(alphabet)
    
    # Find word length
    length = 1
    while True:
        count_up_to_length = _sum_of_variants_up_to_length(length, alphabet_size)
        if index <= count_up_to_length:
            break
        length += 1
    
    offset_for_previous_lengths = _sum_of_variants_up_to_length(length - 1, alphabet_size)
    remainder = index - offset_for_previous_lengths - 1  # zero-based
    
    # Convert to base-N where N is alphabet size
    chars = []
    for _ in range(length):
        cval = remainder % alphabet_size
        chars.append(alphabet[cval])
        remainder //= alphabet_size
    
    return "".join(reversed(chars))


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

    # word = "z"
    # for i in range(1, 32):
    #     identifier = word_to_id(word)
    #     print(f"[{i}] : {identifier} :  : {word}")
    #     word += "z"

    # Read config file
    with open('/home/alex/projects/avax-pw-crack/config.json', 'r') as f:
        config = json.load(f)
    
    variant_id = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    word = id_to_word(config['alphabet'], variant_id)  # Pass alphabet from config
    print(f"The letter variant corresponding to {variant_id} is: [{word}]")

    p_chain_address = restore_p_chain_address(mnemonic, word)
    print(f"P-chain address: {p_chain_address}")


if __name__ == "__main__":
    main()

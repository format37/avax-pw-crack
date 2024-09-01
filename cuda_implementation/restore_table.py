import hashlib
from bip_utils import (
    Bip39SeedGenerator, Bip32Slip10Secp256k1, Bip32KeyIndex, Bech32Encoder
)
from Crypto.Hash import RIPEMD160
import time
from tqdm import tqdm

def find_letter_variant(n):
    if n == 0:
        return 'a'
    alphabet = 'abcdefghijklmnopqrstuvwxyz'
    base = len(alphabet)
    result = []
    while n > 0:
        n -= 1  # Adjust for 0-based indexing
        result.append(alphabet[n % base])
        n //= base
    return ''.join(reversed(result))

def restore_p_chain_address(mnemonic, passphrase, variant):
    # print(f"Restoring P-Chain address for '{passphrase + variant}'")
    seed_bytes = Bip39SeedGenerator(mnemonic).Generate(variant)
    # print(f"Seed bytes: {seed_bytes.hex()}")
    master_key = Bip32Slip10Secp256k1.FromSeed(seed_bytes)
    # print(f"Master key: {master_key}")
    
    child_key = (master_key
                 .ChildKey(Bip32KeyIndex.HardenIndex(44))
                 .ChildKey(Bip32KeyIndex.HardenIndex(9000))
                 .ChildKey(Bip32KeyIndex.HardenIndex(0))
                 .ChildKey(0)
                 .ChildKey(0))
    
    public_key = child_key.PublicKey().RawCompressed().ToBytes()
    sha256_hash = hashlib.sha256(public_key).digest()
    ripemd160_hash = RIPEMD160.new(sha256_hash).digest()
    bech32_address = Bech32Encoder().Encode('avax', ripemd160_hash)
    
    return f'P-{bech32_address}'

# def generate_variant_pchain_table(start, end, mnemonic, base_passphrase):
#     table = []
#     for i in range(start, end):
#         variant = find_letter_variant(i)
#         p_chain_address = restore_p_chain_address(mnemonic, base_passphrase, variant)
#         table.append(f"{i},{variant},{p_chain_address}")
#     return table

def generate_variant_pchain_table(start, end, mnemonic, base_passphrase):
    table = []
    total_iterations = end - start
    
    with tqdm(total=total_iterations, desc="Generating table", unit="iteration") as pbar:
        for i in range(start, end):
            variant = find_letter_variant(i)
            p_chain_address = restore_p_chain_address(mnemonic, base_passphrase, variant)
            table.append(f"{i},{variant},{p_chain_address}")
            pbar.update(1)
    
    return table

def generator():
    # Configuration
    start_variant = 0
    end_variant = 32768  # This will generate variants from 0 to 32767
    # end_variant = 10
    mnemonic = "sell stereo useless course suffer tribe jazz monster fresh excess wire again father film sudden pelican always room attack rubber pelican trash alone cancel"
    base_passphrase = "mnemonic"

    # Generate the table
    variant_pchain_table = generate_variant_pchain_table(start_variant, end_variant, mnemonic, base_passphrase)

    # Print the first few and last few rows
    print("First 5 rows:")
    for row in variant_pchain_table[:5]:
        print(row)

    print("\n...\n")

    print("Last 5 rows:")
    for row in variant_pchain_table[-5:]:
        print(row)

    # Save to a file
    with open('python.csv', 'w') as f:
        f.write("id,variant,p_chain_address\n")  # Header
        for row in variant_pchain_table:
            f.write(f"{row}\n")

    print("\nTable has been generated and saved to 'pyhton.csv'")


def main():
    start_time = time.time()
    generator()
    end_time = time.time()
    print(f"Time elapsed: {end_time - start_time} seconds")

if __name__ == "__main__":
    main()

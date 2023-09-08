import hashlib
from typing import Iterable, Optional, List
from bip_utils import (
    Bip39MnemonicValidator,
    Bip39SeedGenerator, Bip32Slip10Secp256k1, Bip32KeyIndex, Bech32Encoder,
)
from typos import Typos
from Crypto.Hash import RIPEMD160
import json
import os

class Wallet(object):
    def __init__(self, mnemonic: str):
        Bip39MnemonicValidator().Validate(mnemonic)
        self.seed_generator = Bip39SeedGenerator(mnemonic)

    def avax_key(self, passphrase: str):
        print('passphrase', passphrase)
        seed_bytes = self.seed_generator.Generate(passphrase)
        print('seed_bytes', seed_bytes)
        master = Bip32Slip10Secp256k1.FromSeed(seed_bytes)

        # m/44'/9000'/0'
        child = (master
                 .ChildKey(Bip32KeyIndex.HardenIndex(44))
                 .ChildKey(Bip32KeyIndex.HardenIndex(9000))
                 .ChildKey(Bip32KeyIndex.HardenIndex(0))
                 .ChildKey(0))
        print('base_child', child_to_avaxp_address(child.ChildKey(0)))
        return child


def child_to_avaxp_address(child) -> str:
    m = hashlib.sha256()
    m.update(child.PublicKey().RawCompressed().ToBytes())
    
    n = RIPEMD160.new()
    n.update(m.digest())
    
    b32_encoded = Bech32Encoder().Encode('avax', n.digest())
    return f'P-{b32_encoded}'


def generate_10_avax_addresses(passphrase: str, wallet: Wallet) -> List[str]:
    """Generate 10 AVAX addresses for the given passphrase.""" 
    addresses = []
    base_child = wallet.avax_key(passphrase)
    # print('base_child', child_to_avaxp_address(base_child.ChildKey(0)))
    exit()
    for i in range(10):
        child = base_child.ChildKey(i)  # Iterate over the last index to generate 10 keys
        addresses.append(child_to_avaxp_address(child))
    return addresses


def guess_avaxp_address(inputs: Iterable[str], wallet: Wallet, target_addresses: list) -> Optional[str]:
    counter = 0
    for test_passphrase in inputs:
        if len(test_passphrase) != 10:
            continue
        computed_addresses = generate_10_avax_addresses(test_passphrase, wallet)
        # Format with 3 signs, using leading zeros
        counter_formatted = f'{counter:03}'
        # Save the computed addresses to a file
        with open(f'data_0/computed_addresses{counter_formatted}.txt', 'a', encoding='utf-8') as f:
            for address in computed_addresses:
                f.write(f'{address}\n')
        # Save the passphrase to a file
        with open(f'data_0/passphrases{counter_formatted}.txt', 'a', encoding='utf-8') as f:
            f.write(f'{test_passphrase}\n')

        # Check for any matches between the computed addresses and target addresses
        for address in computed_addresses:
            if address in target_addresses:
                print(f'Tried {counter} passphrases, found a match: {test_passphrase}')                
                print('counter_formatted', counter_formatted)
                return test_passphrase
        counter += 1
    print(f'Tried {counter} passphrases, no matches found.')
    return None


if __name__ == "__main__":
    # Remove all files in 'data_0' directory
    for filename in os.listdir('data_0'):
        os.remove(os.path.join('data_0', filename))

    # Read configuration file
    with open('config.json') as json_file:
        data = json.load(json_file)
        mnemonic = data['mnemonic']
        best_guess = data['passphrase']
        p_chain_address = data['p_chain_address']

    # p_chain_address and fake p_chain_address
    expected_avaxp_addresses = [
        p_chain_address,
        p_chain_address.replace('P-', 'Z-'),
    ]

    wallet = Wallet(mnemonic)
    lowercase = False
    typos = Typos(best_guess, max_edit_distance=2, lowercase=lowercase)
    print(guess_avaxp_address(typos, wallet, expected_avaxp_addresses))

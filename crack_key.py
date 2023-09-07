import hashlib
from typing import Iterable, Optional, List
from bip_utils import (
    Bip39MnemonicValidator,
    Bip39SeedGenerator, Bip32Slip10Secp256k1, Bip32KeyIndex, Bech32Encoder,
)
from typos import Typos
from Crypto.Hash import RIPEMD160
import json


class Wallet(object):
    def __init__(self, mnemonic: str):
        Bip39MnemonicValidator().Validate(mnemonic)
        self.seed_generator = Bip39SeedGenerator(mnemonic)

    def avax_key(self, passphrase: str):
        seed_bytes = self.seed_generator.Generate(passphrase)
        master = Bip32Slip10Secp256k1.FromSeed(seed_bytes)

        # m/44'/9000'/0'
        child = (master
                 .ChildKey(Bip32KeyIndex.HardenIndex(44))
                 .ChildKey(Bip32KeyIndex.HardenIndex(9000))
                 .ChildKey(Bip32KeyIndex.HardenIndex(0))
                 .ChildKey(0))
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
    for i in range(10):
        child = base_child.ChildKey(i)  # Iterate over the last index to generate 10 keys
        addresses.append(child_to_avaxp_address(child))
    return addresses


def guess_avaxp_address(inputs: Iterable[str], wallet: Wallet, target_addresses: list) -> Optional[str]:
    counter = 0
    for test_passphrase in inputs:
        computed_addresses = generate_10_avax_addresses(test_passphrase, wallet)
        # Save the computed addresses to a file
        with open(f'data_1/computed_addresses{counter}.txt', 'a', encoding='utf-8') as f:
            for address in computed_addresses:
                f.write(f'{address}\n')

        # Check for any matches between the computed addresses and target addresses
        for address in computed_addresses:
            if address in target_addresses:
                print(f'Tried {counter} passphrases, found a match: {test_passphrase}')                
                return test_passphrase
        counter += 1
    print(f'Tried {counter} passphrases, no matches found.')
    return None


if __name__ == "__main__":
    # Read configuration file
    with open('config.json') as json_file:
        data = json.load(json_file)
        mnemonic = data['mnemonic']
        best_guess = data['passphrase']
        p_chain_address = data['p_chain_address']

    expected_avaxp_addresses = [
        p_chain_address
    ]

    wallet = Wallet(mnemonic)
    lowercase = False
    typos = Typos(best_guess, max_edit_distance=2, lowercase=lowercase)
    print(guess_avaxp_address(typos, wallet, expected_avaxp_addresses))

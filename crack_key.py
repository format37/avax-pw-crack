import hashlib
from typing import Iterable, Optional, List

from bip_utils import (
    Bip39MnemonicValidator,
    Bip39SeedGenerator, Bip32Slip10Secp256k1, Bip32KeyIndex, Bech32Encoder,
)

from typos import Typos


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

    n = hashlib.new('ripemd160')
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
    for test_passphrase in inputs:
        computed_addresses = generate_10_avax_addresses(test_passphrase, wallet)

        # Check for any matches between the computed addresses and target addresses
        for address in computed_addresses:
            if address in target_addresses:
                return test_passphrase
    return None


if __name__ == "__main__":
    mnemonic = "insert mnemonic here"
    best_guess = "guess"
    expected_avaxp_addresses = [
        'P-avax1',
        'P-avax1',
	    'P-avax1',
	    'P-avax1',
	    'P-avax1',
	    'P-avax1',
	    'P-avax1',
	    'P-avax1',
	    'P-avax1',
	    'P-avax1',
    ]

    wallet = Wallet(mnemonic)
    lowercase = False
    typos = Typos(best_guess, max_edit_distance=2, lowercase=lowercase)
    print(guess_avaxp_address(typos, wallet, expected_avaxp_addresses))
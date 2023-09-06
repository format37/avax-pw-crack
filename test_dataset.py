import hashlib
from bip_utils import (
    Bip39MnemonicValidator,
    Bip39SeedGenerator, Bip32Slip10Secp256k1, Bip32KeyIndex, Bech32Encoder,
)
from mnemonic import Mnemonic
from Crypto.Hash import RIPEMD160
import json


# your other methods (e.g., child_to_avaxp_address) here...

class Wallet(object):
    def __init__(self, mnemonic: str):
        print('Validating mnemonic:\n"'+mnemonic+'"\n')
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


def generate_mnemonic_phrase(language="english", num_words=24):
    """
    Generate a mnemonic phrase (seed phrase) based on the BIP-39 standard.
    
    Parameters:
    - language (str): The language for the mnemonic word list. Default is "english".
    - num_words (int): The number of words in the mnemonic phrase. It should be a multiple of 3.
    
    Returns:
    - str: A mnemonic phrase (seed phrase).
    """
    
    if num_words % 3 != 0:
        raise ValueError("The number of words in the mnemonic phrase should be a multiple of 3.")
    
    mnemo = Mnemonic(language)
    mnemonic_phrase = mnemo.generate(strength=num_words * 32 // 3)  # strength is in bits
    return mnemonic_phrase


def generate_single_avax_address(passphrase: str, wallet: Wallet) -> str:
    """Generate a single AVAX p-chain address for the given passphrase."""
    base_child = wallet.avax_key(passphrase)
    return child_to_avaxp_address(base_child.ChildKey(0))


def child_to_avaxp_address(child) -> str:
    m = hashlib.sha256()
    m.update(child.PublicKey().RawCompressed().ToBytes())
    
    n = RIPEMD160.new()
    n.update(m.digest())
    
    b32_encoded = Bech32Encoder().Encode('avax', n.digest())
    return f'P-{b32_encoded}'


def save_configuration(mnemonic_24_str, passphrase, p_chain_address):
    # Save to JSON file
    data = {
        'mnemonic': mnemonic_24_str,
        'passphrase': passphrase,
        'p_chain_address': p_chain_address
    }
    with open('config.json', 'w') as f:
        json.dump(data, f)


def main():
    mnemonic_24_str = generate_mnemonic_phrase()
    print('mnemonic:\n"'+mnemonic_24_str+'"\n')

    # Mnemonic generation and passphrase
    mnemonic = mnemonic_24_str
    passphrase = 'TESTPHRASE'

    # Wallet and p-chain address generation
    wallet = Wallet(mnemonic)
    print('Generating p-chain address for passphrase:\n"'+passphrase+'"\n')
    p_chain_address = generate_single_avax_address(passphrase, wallet)

    print("Generated p-chain address:\n", p_chain_address)

    # Save configuration to JSON file
    save_configuration(mnemonic_24_str, passphrase, p_chain_address)

    print("Configuration saved to config.json")


if __name__ == "__main__":
    main()

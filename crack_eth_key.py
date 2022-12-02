from typing import Iterable, Optional

import web3
from bip_utils import (
    Bip39MnemonicValidator,
    Bip39SeedGenerator, Bip32Slip10Secp256k1, Bip32KeyIndex,
)

from typos import Typos


class Wallet(object):
    def __init__(self, mnemonic: str):
        Bip39MnemonicValidator().Validate(mnemonic)
        self.seed_generator = Bip39SeedGenerator(mnemonic)

    def eth_key(self, passphrase: str):
        seed_bytes = self.seed_generator.Generate(passphrase)
        master = Bip32Slip10Secp256k1.FromSeed(seed_bytes)

        # m/44'/60'/0'/0/0
        child = master.ChildKey(Bip32KeyIndex.HardenIndex(44)) \
            .ChildKey(Bip32KeyIndex.HardenIndex(60)) \
            .ChildKey(Bip32KeyIndex.HardenIndex(0)) \
            .ChildKey(0) \
            .ChildKey(0)

        return child

    def avax_key(self, passphrase: str):
        seed_bytes = self.seed_generator.Generate(passphrase)
        master = Bip32Slip10Secp256k1.FromSeed(seed_bytes)

        # m/44'/9000'/0'
        child = master.ChildKey(Bip32KeyIndex.HardenIndex(44)) \
            .ChildKey(Bip32KeyIndex.HardenIndex(9000)) \
            .ChildKey(Bip32KeyIndex.HardenIndex(0))

        return child


def guess_eth_address(inputs: Iterable[str], wallet: Wallet, target_eth_address: str) -> Optional[str]:
    for test_passphrase in inputs:
        child = wallet.eth_key(test_passphrase)
        eth_account = web3.Account.from_key(child.PrivateKey().Raw().ToHex())
        eth_address = eth_account.address

        if eth_address == target_eth_address:
            return test_passphrase


if __name__ == "__main__":
    mnemonic = "mixed snap before near whale there silent behave inform sight output keep ability bind target engage chief month axis belt bicycle timber slam glow"
    best_guess = "myfakephraze"
    expected_eth_address = '0xdc22f43BEFeb27E5B8185Ae6d336b41295998526'

    # myfakephrase is the actual password.
    # Used https://iancoleman.io/bip39/
    # Put the mneumonic and real key in. Switch coin to eth. Scroll down and grab the first address.

    wallet = Wallet(mnemonic)
    typos = Typos(best_guess, max_edit_distance=2)
    print(guess_eth_address(typos, wallet, expected_eth_address))

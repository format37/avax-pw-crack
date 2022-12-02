import hashlib
from typing import Iterable, Optional

import web3
from bip_utils import (
    Bip39MnemonicValidator,
    Bip39SeedGenerator, Bip32Slip10Secp256k1, Bip32KeyIndex, Bech32Encoder,
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
            .ChildKey(Bip32KeyIndex.HardenIndex(0)) \
            .ChildKey(0) \
            .ChildKey(0)

        return child


def child_to_eth_address(child) -> str:
    eth_account = web3.Account.from_key(child.PrivateKey().Raw().ToHex())
    return eth_account.address


def guess_eth_address(inputs: Iterable[str], wallet: Wallet, target_address: str) -> Optional[str]:
    for test_passphrase in inputs:
        child = wallet.eth_key(test_passphrase)
        computed_address = child_to_eth_address(child)

        if computed_address == target_address:
            return test_passphrase


def child_to_avaxp_address(child) -> str:
    m = hashlib.sha256()
    m.update(child.PublicKey().RawCompressed().ToBytes())

    n = hashlib.new('ripemd160')
    n.update(m.digest())

    b32_encoded = Bech32Encoder().Encode('avax', n.digest())
    return f'P-{b32_encoded}'


def guess_avaxp_address(inputs: Iterable[str], wallet: Wallet, target_address: str) -> Optional[str]:
    for test_passphrase in inputs:
        child = wallet.avax_key(test_passphrase)
        computed_address = child_to_avaxp_address(child)

        if computed_address == target_address:
            return test_passphrase


if __name__ == "__main__":
    mnemonic = "mixed snap before near whale there silent behave inform sight output keep ability bind target engage chief month axis belt bicycle timber slam glow"
    # myfakephrase is the actual password.
    best_guess = "myfakephraze"
    expected_eth_address = '0xdc22f43BEFeb27E5B8185Ae6d336b41295998526'
    expected_avaxp_address = 'P-avax1kp9uggwxkqhygljkpr0cls378sqwrxfw55qcka'

    wallet = Wallet(mnemonic)

    # Can take this and import into https://wallet.avax.network to get the corresponding
    # c/p chain addresses with the 25th word.
    # Can also use https://iancoleman.io/bip39/ but it only supports eth and not avax.
    # print(wallet.eth_key('myfakephrase').PrivateKey().Raw().ToHex())
    # print(wallet.avax_key('myfakephrase').PrivateKey().Raw().ToHex())

    typos = Typos(best_guess, max_edit_distance=2)

    # print(guess_eth_address(typos, wallet, expected_eth_address))
    print(guess_avaxp_address(typos, wallet, expected_avaxp_address))

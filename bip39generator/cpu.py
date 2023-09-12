import bip_utils
from bip_utils import Bip39SeedGenerator
# import pkg_resources
import os
import inspect

# Function to add hyphens to the hex string after every 4 bytes (8 characters)
def add_hyphens_to_hex(hex_str):
    return '-'.join([hex_str[i:i+8] for i in range(0, len(hex_str), 8)])

# print(pkg_resources.get_distribution("bip_utils").version)
print(os.path.dirname(inspect.getfile(bip_utils)))

mnemonic = 'sell stereo useless course suffer tribe jazz monster fresh excess wire again father film sudden pelican always room attack rubber pelican trash alone cancel'
passphrase = 'TESTPHRASG'
seed_generator = Bip39SeedGenerator(mnemonic)
seed_bytes = seed_generator.Generate(passphrase)

print('len:', len(seed_bytes))
print('seed_bytes:', seed_bytes)
# Convert from bytes to number
seed_num = int.from_bytes(seed_bytes, byteorder='big')
print('seed_num:', seed_num)
hex_result = seed_bytes.hex()
hex_result_with_hyphens = add_hyphens_to_hex(hex_result)
print('result:', hex_result_with_hyphens)
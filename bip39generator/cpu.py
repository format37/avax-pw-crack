import bip_utils
from bip_utils import Bip39SeedGenerator
# import pkg_resources
import os
import inspect

# print(pkg_resources.get_distribution("bip_utils").version)
print(os.path.dirname(inspect.getfile(bip_utils)))

mnemonic = 'sell stereo useless course suffer tribe jazz monster fresh excess wire again father film sudden pelican always room attack rubber pelican trash alone cancel'
passphrase = 'TESTPHRASG'
seed_generator = Bip39SeedGenerator(mnemonic)
seed_bytes = seed_generator.Generate(passphrase)

print(len(seed_bytes))
print(seed_bytes)

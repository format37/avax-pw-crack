# https://www.dcode.fr/pbkdf2-hash
import hashlib
from bip_utils.utils.misc import AlgoUtils

# Function to add hyphens to the hex string after every 4 bytes (8 characters)
def add_hyphens_to_hex(hex_str):
    return '-'.join([hex_str[i:i+8] for i in range(0, len(hex_str), 8)])

password = 'sell stereo useless course suffer tribe jazz monster fresh excess wire again father film sudden pelican always room attack rubber pelican trash alone cancel'
password = AlgoUtils.Encode(password)
print('# password:', password)
salt = 'mnemonicTESTPHRASG'
salt = AlgoUtils.Encode(salt)
print('# salt:', salt)
itr_num = 2048
dklen = 64
result = hashlib.pbkdf2_hmac("sha512", password, salt, itr_num, dklen)
# result = hashlib.pbkdf2_hmac("sha256", password, salt, itr_num, dklen)
hex_result = result.hex()
hex_result_with_hyphens = add_hyphens_to_hex(hex_result)
print('result:', hex_result_with_hyphens)
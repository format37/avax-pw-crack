def find_variant_id(s):
    alphabet = 'abcdefghijklmnopqrstuvwxyz'
    base = len(alphabet)
    result = 0
    
    for char in s:
        result = result * base + alphabet.index(char) + 1
    
    return result

def find_letter_variant(n):
    alphabet = 'abcdefghijklmnopqrstuvwxyz'
    base = len(alphabet)
    result = []
    
    while n > 0:
        n -= 1  # Adjust for 0-based indexing
        result.append(alphabet[n % base])
        n //= base
    
    return ''.join(reversed(result))

# variant_number = 87239553796647
# variant_number = 2147482623
# variant_number = 18446744073709551614
# variant_number = 46261
# variant_number = 3337400
# variant_number = 131071
# variant_number = 262143
# variant_number = 140737488355328
# variant_number = 1 # a # P-avax12qh90yv6untxrn6tp9gg4dha70g2rpjqesdny8
# variant_number = 32768 # avlh # P-avax1hs8j43549he3tuxd3wupp3nr0n9l3j80r4539a
# variant_number = 65536 # crxp # P-avax1yj5pwqc0fcx9q0jawsuqfq2e6x9mjw4z5exyp4
# variant_number = 131072 # gkwf # P-avax1hkq2jc35k4m8llchp5lpklmg2l3yw2emy4afng
variant_number = 262144 # nwtl # P-avax1vl2vfvvpm79fnrtxuvcryx9wgfj95gpkl7r3g8

result = find_letter_variant(variant_number)
print(f"The letter variant corresponding to {variant_number} is: {result}")

# passphrase = 'passphrase'
# passphrase = 'book'
passphrase = 'czz'
variant_id = find_variant_id(passphrase)
print(f"The variant ID corresponding to '{passphrase}' is: {variant_id}")
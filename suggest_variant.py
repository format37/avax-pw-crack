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
variant_number = 3337400
result = find_letter_variant(variant_number)
print(f"The letter variant corresponding to {variant_number} is: {result}")

# passphrase = 'passphrase'
passphrase = 'book'
variant_id = find_variant_id(passphrase)
print(f"The variant ID corresponding to '{passphrase}' is: {variant_id}")
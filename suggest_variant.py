def find_letter_variant(n):
    alphabet = 'abcdefghijklmnopqrstuvwxyz'
    base = len(alphabet)
    result = []
    
    while n > 0:
        n -= 1  # Adjust for 0-based indexing
        result.append(alphabet[n % base])
        n //= base
    
    return ''.join(reversed(result))

variant_number = 32767
result = find_letter_variant(variant_number)
print(f"The letter variant corresponding to {variant_number} is: {result}")

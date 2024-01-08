# Correct the initialization of the BIGNUM class to properly break the hexadecimal input string into 64-bit words in little endian format.

class BIGNUM:

    def __init__(self, hex_str, max_words=4):

        self.d = [0] * max_words

        # Pad the hex string to fit into the chunks of 64-bit words (16 hex characters each).

        hex_str = hex_str.rjust(max_words * 16, '0')

        # Break down the hex string into 64-bit words, obeying little-endian ordering.

        for i in range(0, len(hex_str), 16):

            word = int(hex_str[-(i + 16):len(hex_str) - i], 16)

            self.d[i//16] = word

        self.top = max_words



    def find_top(self):

        # Return the index of the highest non-zero word + 1, or 1 if all words are 0.

        for i in reversed(range(len(self.d))):

            if self.d[i] != 0:

                return i + 1

        return 1



    def to_hex_string(self):

        # Convert to a hexadecimal string in big-endian format (most-significant word first).

        return ''.join(f'{w:016x}' for w in reversed(self.d[:self.top])).lstrip('0')



def bn_subtract(result, a, b):

    # Perform subtraction with borrow, as earlier.

    borrow = 0

    for i in range(result.top):

        ai = a.d[i] if i < a.top else 0

        bi = b.d[i] if i < b.top else 0

        dist = ai - bi - borrow

        if dist < 0:

            borrow = 1

            dist += 1 << 64

        else:

            borrow = 0

        result.d[i] = dist

    result.top = result.find_top()



# Re-run the subtraction with newly defined classes and functions, using the correctly initialized BIGNUM instances.

a = BIGNUM("B0C00000100001234567890ABCDEF", max_words=3)

b = BIGNUM("A0B000000F1000000000000000", max_words=3)

result = BIGNUM('0', max_words=3)



bn_subtract(result, a, b)

result_hex_string = result.to_hex_string() # Convert to big-endian hex-string for comparison

expected_result = "B0B5F5000FFF10234567890ABCDEF"



# Compare the result with the expected value and display both.

# print((result_hex_string, result_hex_string == expected_result))
print(result_hex_string)



"""# Correct test values for subtraction to match little-endian format expected by BIGNUM
test_cases_corrected = [
    ([0x1], [0x0]),
    ([0xDEF, 0x10], [0xABC, 0x8]),  # Reversed order for little-endian
    ([0x1234567890ABCDEF, 0x10000, 0xc0, 0xb0], [0x1000000000000000, 0xF, 0xb0, 0xa0])  # Reversed order for little-endian
]

for idx, (a_words, b_words) in enumerate(test_cases_corrected, 1):
    a = BIGNUM(a_words)
    b = BIGNUM(b_words)
    result = BIGNUM([], max_words=20)

    # Using the verbose version of the function for the 4-word test for clarity
    if idx == 3:
        bn_subtract(result, a, b)
    else:
        # Use the non-verbose version for other tests
        bn_subtract(result, a, b)

    print(f"\nTest {idx}:")
    print("a:", a)
    print("b:", b)
    print("result:", result)

"""


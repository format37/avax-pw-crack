# Correct implementation of BIGNUM class and bn_subtract function

class BIGNUM:

    def __init__(self, words, max_words=4):

        self.d = [0] * max_words

        for i, word in enumerate(words):

            self.d[i] = word

        self.top = self.find_top()



    def find_top(self):

        for i in reversed(range(len(self.d))):

            if self.d[i] != 0:

                return i + 1

        return 0



    def __repr__(self):

        return ' '.join(f'{word:016x}' for word in reversed(self.d[:self.top]))



def bn_subtract(result, a, b):

    borrow = 0

    max_words = max(a.top, b.top)

    for i in range(max_words):

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


def hex_to_chunks(hex_str, chunk_size=16):

    """Converts a hex string into a list of integer chunks (little-endian order)."""

    # Ensure the hex string has an even number of digits for chunking

    hex_str = hex_str.rjust(chunk_size * ((len(hex_str) + chunk_size - 1) // chunk_size), '0')

    # Convert the hex string to little-endian ordered integer chunks

    return [int(hex_str[i:i + chunk_size], 16) for i in range(0, len(hex_str), chunk_size)][::-1]



# Adjusted initial values for a and b for Test 3

a_chunks_test3 = hex_to_chunks("B0C00000100001234567890ABCDEF", chunk_size=16)

b_chunks_test3 = hex_to_chunks("A0B000000F1000000000000000", chunk_size=16)



# Initialize BIGNUM instances for Test 3 with little-endian ordered chunks

a_test3 = BIGNUM(a_chunks_test3)

b_test3 = BIGNUM(b_chunks_test3)

result_test3 = BIGNUM([0] * max(len(a_chunks_test3), len(b_chunks_test3)))



# Perform the subtraction for Test 3

bn_subtract(result_test3, a_test3, b_test3)



# Convert the result to a human-readable hex string (big-endian)

result = ' '.join(f'{word:016x}' for word in reversed(result_test3.d[:result_test3.top])).upper()
print(result)

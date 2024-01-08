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



# Let's implement a loop test for the given list of cases in Python first



# Helper function to convert a hex string to a BIGNUM instance considering little-endian order

def create_bignum_from_hex(hex_str, max_words=4):

    # Ensure the string length is a multiple of 16 (64 bits)

    hex_str = hex_str.rjust(((len(hex_str) + 15) // 16) * 16, '0')

    words = [int(hex_str[i:i + 16], 16) for i in reversed(range(0, len(hex_str), 16))]

    return BIGNUM(words, max_words)


# List of test cases - hex strings for 'a' and 'b'

test_values_a = ["1", "10DEF", "B0C00000100001234567890ABCDEF"]

test_values_b = ["0", "8ABC", "A0B000000F1000000000000000"]


# Function to test BIGNUM subtraction for a list of hex-string cases

def bignum_subtraction_tests(test_values_a, test_values_b):

    for test_val_a, test_val_b in zip(test_values_a, test_values_b):

        a = create_bignum_from_hex(test_val_a)

        b = create_bignum_from_hex(test_val_b)

        result = BIGNUM([0] * max(len(a.d), len(b.d)))

        bn_subtract(result, a, b)

        

        # Display the result in big-endian format as a hex string

        result_str = ''.join(f'{word:016x}' for word in reversed(result.d[:result.top])).upper().lstrip('0')

        print(f"a: {test_val_a}, b: {test_val_b}, a-b: {result_str}")



bignum_subtraction_tests(test_values_a, test_values_b)


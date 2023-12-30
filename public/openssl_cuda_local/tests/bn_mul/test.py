def simulate_word_mul(a, b, word_size=64):

    """

    Simulates multi-word multiplication like in CUDA, but in Python.

    :param a: hex string operand a

    :param b: hex string operand b

    :param word_size: the size of the word in bits

    :return: hex string result of the multiplication

    """

    # Convert the hex strings to binary representations with fixed word size

    a_bin = bin(int(a, 16))[2:].zfill(word_size)

    b_bin = bin(int(b, 16))[2:].zfill(word_size)

    

    # Initialize the product with zeros

    product_bin = '0' * (len(a_bin) + len(b_bin))

    

    # Calculate the multiplication using the binary strings, simulating word-by-word multiplication

    for i, digit_a in enumerate(reversed(a_bin)):

        if digit_a == '1':

            # Shift b to the left by i positions and add it to the product

            temp_b_bin = b_bin + '0' * i

            product_bin = bin(int(product_bin, 2) + int(temp_b_bin, 2))[2:].zfill(len(product_bin))

    

    # Trim the result to the word size, drop leading unnecessary zeros (simulate fixed word size)

    product_bin = product_bin[-(2 * word_size):]

    

    # Convert the binary string back to a hex string

    product_hex = hex(int(product_bin, 2))

    

    return product_hex



# Testing the simulate_word_mul function with 2-word (64-bit each) multiplication
test_values_a = ["1", "F", "FF", "ABC", "1234567890ABCDEF", "10", "FFFFFFFFFFFFFFFFF"]
test_values_b = ["2", "F", "101", "10", "FEDCBA0987654321", "10", "10000000000000000"]
for i in range(len(test_values_a)):
    print(
        "a: ", test_values_a[i], 
        "b: ", test_values_b[i], 
        "result: ",  
        simulate_word_mul(test_values_a[i], test_values_b[i], word_size=64)
        )

# Given hexadecimal value
hex_value = "bbc611b700cbdb5c8361c267c2587992cac0bb2d97f0a86f6334ec00a7210d9c"

# Convert the hexadecimal string to a binary string, then to a list of integers (0 or 1)
binary_string = bin(int(hex_value, 16))[2:].zfill(256)  # Ensure 256 bits
binary_values = [int(bit) for bit in binary_string]

# Create the table with index and corresponding binary value
index_binary_pairs = [(i, bit) for i, bit in enumerate(binary_values)]

# Reverse the order of the index_binary_pairs list
reversed_index_binary_pairs = list(enumerate(reversed(binary_values)))

# Print the reversed table
for index, bit in reversed_index_binary_pairs:
    print(f"{index}: {bit}")
    # bit_inversed = 1 if bit == 0 else 0
    # print(f"{index}: {bit_inversed}")

# Given a list of words. Each word is 16 hex symbols from '0' to 'F'.

# Need to implement the extracting values from S to N. 
# The numerator starts from left, for example:
# [
#     [47, 46, 45, 44, 43, 42, 41, 40, 39, 38, 37, 36, 35, 34, 33, 32],
#     [31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16],
#     [15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0]
# ]

# The extracted sequence should shift to the left.
# For example:
# words = ['0284619f7ea27d52','e75656ab232452bf','298b56ae54fe2c3d']
# f(words, 0,7) = ['0000000000000000','0000000000000000','0000000004fe2c3d']
# f(words, 3,20) = ['0000000000000000','0000000000000005','2bf298b56ae54fe2']
# f(words, 22,45) = ['0000000000000000','0000000004619f7e','a27d52e75656ab23']

def f(words, S, N):
    # Concatenate all words together
    all_words = ''.join(words)
    # Get the length of the substring
    full_length = len(all_words)
    # Get the start_symbol
    start_symbol = full_length - S
    # Get the final_symbol
    final_symbol = full_length - N
    # Get the substring from start_symbol to the final_symbol
    substring = all_words[final_symbol:start_symbol]
    # Get the length of the substring
    substring_length = len(substring)
    # Calculate the padding
    padding = full_length - substring_length
    # return ['0' * padding + substring]
    result_concatenated = '0' * padding + substring
    # Calculate the count of words
    count = len(words)
    # Create the result list
    result = []
    # Iterate over the count
    for i in range(count):
        # Get the start index
        start_index = i * 16
        # Get the end index
        end_index = (i + 1) * 16
        # Append the result
        result.append(result_concatenated[start_index:end_index])
    # Return the result
    return result


def main():
    words = ['0284619f7ea27d52', 'e75656ab232452bf', '298b56ae54fe2c3d']
    print('\nWords:')
    print([word for word in words])
    print('\nTests:')
    print(f(words, 0, 7))
    print(f(words, 3, 20))
    print(f(words, 22, 45))


if __name__ == '__main__':
    main()

def get_next_variant(current, alphabet):
    # Convert current variant to list for easier manipulation
    chars = list(current)
    
    # Start from rightmost position
    pos = len(chars) - 1
    
    while pos >= 0:
        # Find current char position in alphabet
        current_char_index = alphabet.index(chars[pos])
        
        # If we haven't reached the last character in alphabet
        if current_char_index < len(alphabet) - 1:
            # Replace current char with next char in alphabet
            chars[pos] = alphabet[current_char_index + 1]
            return ''.join(chars)
        else:
            # Reset current position to first char and continue with next position
            chars[pos] = alphabet[0]
            pos -= 1
    
    # If we're here, we need to add one more character
    return alphabet[0] * (len(current) + 1)

def generate_variants(start_passphrase, end_passphrase, alphabet):
    current = start_passphrase
    with open("passphrases.txt", "w") as file:
        file.write(f"Starting variant generation from {start_passphrase} to {end_passphrase}\n")
        while True:
            # print(current)
            # Append current to file
            file.write(current + '\n')
            
            if current == end_passphrase:
                break
                
            current = get_next_variant(current, alphabet)
    print("Done")

# Read from config
alphabet = "ABCDFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 !@#$%^&*()-_=+[]{};:'\",.<>?/\\|~"
start_passphrase = "A"
end_passphrase = "AB"

generate_variants(start_passphrase, end_passphrase, alphabet)
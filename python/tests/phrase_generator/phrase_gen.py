import json

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

def id_to_word(alphabet, n):
    base = len(alphabet)
    result = []
    n += 1  # Adjust for 1-based indexing
    while n > 0:
        n -= 1  # Adjust for 0-based indexing
        result.append(alphabet[n % base])
        n //= base
    
    return ''.join(reversed(result))

def generate_variants(start_passphrase, end_passphrase, alphabet):
    current = start_passphrase
    word_id = 1
    with open("passphrases.txt", "w") as file:
        # file.write(f"Starting variant generation from {start_passphrase} to {end_passphrase}\n")
        while True:
            # print(current)
            # current_mock = id_to_word(alphabet, word_id)
            # Append current to file
            # file.write(f"[{current_mock}] {current} \n")
            # if current != current_mock:
            #     print(f"Error: {current} != {current_mock}")
            #     break
            file.write(f"{start_passphrase}:{current}\n")
            
            if current == end_passphrase:
                break
                
            current = get_next_variant(current, alphabet)
            word_id += 1
    print("Done")

def generate_from_words(alphabet):
    # Read from config
    # alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 !@#$%^&*()-_=+[]{};:'\",.<>?/\\|~"
    start_passphrase = "A"
    end_passphrase = "BF"

    generate_variants(start_passphrase, end_passphrase, alphabet)

def generate_from_id(alphabet, start_id, end_id):
    start_passphrase = id_to_word(alphabet, start_id)
    end_passphrase = id_to_word(alphabet, end_id)
    # generate_variants(start_passphrase, end_passphrase, alphabet)
    print(f"[{start_passphrase}:{end_passphrase}]")

def main():
    with open("config.json") as json_file:
        config = json.load(json_file)
    # generate_from_words(config["alphabet"])
    search_area = config["search_area"]
    for i in range(search_area["start"], search_area["end"], search_area["step"]):
        print(f'Generation [{search_area["start"]}:{i}]')
        generate_from_id(search_area["alphabet"], search_area["start"], i)
        # input(f"[{i}] Press Enter to continue...")
    print("Done")
    

if __name__ == "__main__":
    main()

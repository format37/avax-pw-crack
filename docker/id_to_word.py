#!/usr/bin/env python3
import json
import argparse

def id_to_word(alphabet, n):
    """Convert numeric ID to word using given alphabet"""
    base = len(alphabet)
    result = []
    n += 1  # Adjust for 1-based indexing
    while n > 0:
        n -= 1  # Adjust for 0-based indexing
        result.append(alphabet[n % base])
        n //= base
    return ''.join(reversed(result))

def main():
    # Set up argument parser
    parser = argparse.ArgumentParser(description='Convert numeric ID to word using alphabet from config')
    parser.add_argument('id', type=int, help='Numeric ID to convert')
    parser.add_argument('--config', type=str, default='config.json', 
                        help='Path to config file (default: config.json)')

    args = parser.parse_args()

    # Read configuration
    try:
        with open(args.config, 'r') as f:
            config = json.load(f)
            alphabet = config['alphabet']
    except FileNotFoundError:
        print(f"Error: Config file '{args.config}' not found")
        return
    except KeyError:
        print("Error: Config file does not contain 'alphabet' key")
        return
    except json.JSONDecodeError:
        print("Error: Invalid JSON in config file")
        return

    # Convert ID to word
    try:
        word = id_to_word(alphabet, args.id)
        print(word)
    except Exception as e:
        print(f"Error converting ID to word: {str(e)}")

if __name__ == '__main__':
    main()


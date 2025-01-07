#!/usr/bin/env python3
import json
import argparse
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from p_chain_tools import word_to_id

def main():
    # Set up argument parser
    parser = argparse.ArgumentParser(description='Convert word to numeric ID using alphabet from config')
    parser.add_argument('word', type=str, help='Word to convert to ID')
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

    # Convert word to ID
    try:
        id = word_to_id(alphabet, args.word)
        print(id)
    except ValueError as e:
        print(f"Error: {str(e)}")
    except Exception as e:
        print(f"Error converting word to ID: {str(e)}")

if __name__ == '__main__':
    main()


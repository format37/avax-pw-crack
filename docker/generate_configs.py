import json
import os
from pathlib import Path
import yaml

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

def word_to_id(alphabet, word):
    """Convert word to numeric ID using given alphabet"""
    base = len(alphabet)
    id = 0
    for char in word:
        id = id * base + alphabet.index(char)
    return id

def generate_config(template_config, start_word, end_word, device_id):
    """Generate config for specific device and range"""
    config = template_config.copy()
    config['start_passphrase'] = start_word
    config['end_passphrase'] = end_word
    return config

def generate_compose_config():
    # Read template config
    with open('config.json', 'r') as f:
        template_config = json.load(f)
    
    alphabet = template_config['alphabet']
    start_word = template_config['start_passphrase']
    end_word = template_config['end_passphrase']
    num_devices = template_config['cuda']['instances']
    
    # Calculate numeric IDs
    start_id = word_to_id(alphabet, start_word)
    end_id = word_to_id(alphabet, end_word)
    
    # Calculate total number of words to process (including end word)
    total_words = end_id - start_id + 1
    
    # Calculate words per device (rounded up to avoid gaps)
    words_per_device = (total_words + num_devices - 1) // num_devices
    
    # Create configs directory if it doesn't exist
    configs_dir = Path('configs')
    configs_dir.mkdir(exist_ok=True)
    
    # Prepare docker-compose services
    services = {}
    
    for device_id in range(num_devices):
        # Calculate range for this device
        device_start_id = start_id + (device_id * words_per_device)
        device_end_id = min(device_start_id + words_per_device - 1, end_id)
        
        # Skip if this device's range would start beyond the end
        if device_start_id > end_id:
            continue
        
        # Convert IDs to words
        device_start_word = id_to_word(alphabet, device_start_id)
        device_end_word = id_to_word(alphabet, device_end_id)
        
        print(f"Device {device_id}: {device_start_word} to {device_end_word}")
        
        # Generate device config
        device_config = generate_config(
            template_config,
            device_start_word,
            device_end_word,
            device_id
        )
        
        # Save device config
        config_path = configs_dir / f'config_{device_id}.json'
        with open(config_path, 'w') as f:
            json.dump(device_config, f, indent=2)
        
    #     # Create service configuration
    #     service_name = f'searcher_{device_id}'
    #     services[service_name] = {
    #         'image': 'your-cuda-image:latest',  # Replace with your image name
    #         'runtime': 'nvidia',
    #         'environment': [
    #             f'NVIDIA_VISIBLE_DEVICES={device_id}'
    #         ],
    #         'volumes': [
    #             f'./configs/config_{device_id}.json:/config.json:ro',
    #             f'./results/result_{device_id}.txt:/app/result.txt',
    #             f'./results/time_{device_id}.txt:/app/time.txt'
    #         ]
    #     }
    
    # # Create docker-compose config
    # compose_config = {
    #     'version': '3.8',
    #     'services': services
    # }
    
    # # Create results directory
    # Path('results').mkdir(exist_ok=True)
    
    # # Save docker-compose.yml
    # with open('docker-compose.yml', 'w') as f:
    #     yaml.dump(compose_config, f, sort_keys=False)

if __name__ == '__main__':
    generate_compose_config()
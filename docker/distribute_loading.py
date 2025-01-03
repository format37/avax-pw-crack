import json
from pathlib import Path
import numpy as np
import pandas as pd

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

def calculate_device_ranges(config_path, penalties_file):
    """Calculate device ranges based on performance penalties and configuration"""
    # Read configuration
    with open(config_path, 'r') as f:
        config = json.load(f)
    
    # Extract necessary configuration
    alphabet = config['alphabet']
    start_word = config['start_passphrase']
    end_word = config['end_passphrase']
    num_devices = config['cuda']['instances']
    
    # Read penalties from CSV and filter for the required number of devices
    penalties_df = pd.read_csv(penalties_file)
    penalties_df = penalties_df[penalties_df['device_id'] < num_devices]
    
    # Verify we have enough device entries in the penalties file
    if len(penalties_df) != num_devices:
        raise ValueError(f"Not enough device entries in penalties file for {num_devices} devices")
    
    # Sort by device_id to ensure correct order
    penalties_df = penalties_df.sort_values('device_id')
    penalties = penalties_df['penalty'].tolist()
    biases = penalties_df['bias'].tolist()
    
    # Calculate weights (inverse of penalties)
    weights = 1 / np.array(penalties)
    # Normalize weights to sum to 1
    weights = weights / weights.sum()
    
    # Calculate numeric range
    start_id = word_to_id(alphabet, start_word)
    end_id = word_to_id(alphabet, end_word)
    total_range = end_id - start_id + 1
    
    # Calculate device ranges
    ranges = []
    current_id = start_id
    cumulative_size = 0
    
    for i, weight in enumerate(weights[:-1]):  # Process all but the last device
        # Calculate range size for this device using ceiling to prevent gaps
        range_size = int(np.ceil(total_range * weight))
        
        # Adjust range size to prevent overshooting
        if cumulative_size + range_size >= total_range:
            range_size = total_range - cumulative_size
        
        device_end_id = current_id + range_size - 1
        
        # Convert IDs to words
        device_start_word = id_to_word(alphabet, current_id)
        device_end_word = id_to_word(alphabet, device_end_id)
        
        # Create device config
        device_config = config.copy()
        device_config['start_passphrase'] = device_start_word
        device_config['end_passphrase'] = device_end_word
        
        ranges.append({
            'device_id': i,
            'start_word': device_start_word,
            'end_word': device_end_word,
            'weight': weight,
            'range_size': range_size,
            'config': device_config
        })
        
        current_id = device_end_id + 1
        cumulative_size += range_size
    
    # Last device gets the remaining range
    if cumulative_size < total_range:
        device_config = config.copy()
        device_config['start_passphrase'] = id_to_word(alphabet, current_id)
        device_config['end_passphrase'] = end_word  # Use original end word
        
        ranges.append({
            'device_id': num_devices - 1,
            'start_word': id_to_word(alphabet, current_id),
            'end_word': end_word,
            'weight': weights[-1],
            'range_size': total_range - cumulative_size,
            'config': device_config
        })
    
    return ranges

def main():
    # Configuration
    config_path = 'config.json'
    penalties_file = 'penalties.csv'  # Updated file name
    
    # Calculate ranges
    ranges = calculate_device_ranges(config_path, penalties_file)
    
    # Create configs directory if it doesn't exist
    configs_dir = Path('configs')
    configs_dir.mkdir(exist_ok=True)

    # Remove all existing files in configs directory
    for file in configs_dir.glob('*'):
        file.unlink()
    
    # Print results and save individual configs
    print("\nDevice Ranges:")
    print("-" * 60)
    penalties_df = pd.read_csv(penalties_file)
    for r in ranges:
        device_id = r['device_id']
        # Filter penalties_df by device_id to get the correct row
        device_data = penalties_df[penalties_df['device_id'] == device_id].iloc[0]
        penalty = device_data['penalty']
        bias = device_data['bias']
        forecast_time = penalty * r['range_size'] + bias
        
        print(f"Device {device_id}:")
        print(f"  Weight: {r['weight']:.2%}")
        print(f"  Range Size: {r['range_size']}")
        print(f"  Start: {r['start_word']}")
        print(f"  End: {r['end_word']}")
        print(f"  Forecast Time: {forecast_time:.2f} seconds ({forecast_time/3600:.2f} hours)")
        print()
        
        # Save individual device config
        config_path = configs_dir / f'config_{r["device_id"]}.json'
        with open(config_path, 'w') as f:
            json.dump(r['config'], f, indent=2)
    
    # Save summary to JSON
    with open('device_ranges.json', 'w') as f:
        summary = {
            'devices': [{k: v for k, v in r.items() if k != 'config'} for r in ranges],
            'total_range': sum(r['range_size'] for r in ranges),
            'alphabet': ranges[0]['config']['alphabet']
        }
        json.dump(summary, f, indent=2)

if __name__ == '__main__':
    main()

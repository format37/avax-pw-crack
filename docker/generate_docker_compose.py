import json
from pathlib import Path
import yaml

def read_configs(configs_dir: str) -> list:
    """Read all JSON config files from the specified directory."""
    configs_path = Path(configs_dir)
    configs = []
    
    for config_file in sorted(configs_path.glob('config_*.json')):
        with open(config_file, 'r') as f:
            config = json.load(f)
            # Extract device ID from filename (config_X.json)
            device_id = int(config_file.stem.split('_')[1])
            configs.append((device_id, config))
    
    return configs

def create_service_config(device_id: int, config_file: str) -> dict:
    """Create service configuration for a single device."""
    service_name = f'searcher_{device_id}'
    
    # Get CUDA architecture from the config file
    with open(config_file, 'r') as f:
        config = json.load(f)
        arch = config.get('cuda', {}).get('architecture', 'sm_86')  # default to sm_86 if not specified
    
    return {
        'image': f'avax:{arch}',  # Using the architecture-specific image
        'runtime': 'nvidia',
        'environment': [
            f'NVIDIA_VISIBLE_DEVICES={device_id}'
        ],
        'volumes': [
            f'./configs/config_{device_id}.json:/app/config.json:ro',  # Mount config as read-only
            f'./results/result_{device_id}.txt:/app/result.txt',       # Mount result file
            f'./results/time_{device_id}.txt:/app/time.txt'           # Mount timing file
        ]
    }

def generate_compose_file(configs_dir: str = 'configs', output_file: str = 'docker-compose.yml'):
    """Generate docker-compose.yml file from config files."""
    # Ensure results directory exists
    Path('results').mkdir(exist_ok=True)
    
    # Read all configs
    configs = read_configs(configs_dir)
    
    # Create services dictionary
    services = {}
    for device_id, _ in configs:
        config_file = Path(configs_dir) / f'config_{device_id}.json'
        services[f'searcher_{device_id}'] = create_service_config(device_id, config_file)
    
    # Create compose configuration
    compose_config = {
        'version': '3.8',
        'services': services
    }
    
    # Write docker-compose.yml
    with open(output_file, 'w') as f:
        yaml.dump(compose_config, f, sort_keys=False)
    
    print(f"Generated {output_file} with {len(services)} services")

if __name__ == '__main__':
    generate_compose_file()

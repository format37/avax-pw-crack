import numpy as np
from sklearn.linear_model import LinearRegression
import matplotlib.pyplot as plt
import csv
import sys
from pathlib import Path
import json
import pycuda.driver as cuda
import subprocess
from typing import Tuple, List, Optional
from combine_results import combine_temp_results

def get_device_id_by_pci_bus_id(target_pci_id: str) -> Optional[int]:
    """Get CUDA device ID from PCI bus ID."""
    cuda.init()
    for i in range(cuda.Device.count()):
        device = cuda.Device(i)
        # Strip leading zeros and domain for comparison
        device_pci = device.pci_bus_id().replace('0000:', '')
        target_pci = target_pci_id.replace('00000000:', '')
        if device_pci == target_pci:
            return i
    return None

def get_docker_gpu_pci_id(device_index: int) -> Optional[str]:
    """Get GPU PCI ID from Docker device index."""
    try:
        # Get GPU info in JSON format
        result = subprocess.run(['nvidia-smi', '-L'], capture_output=True, text=True)
        if result.returncode != 0:
            raise Exception("Failed to run nvidia-smi")
            
        lines = result.stdout.strip().split('\n')
        if device_index >= len(lines):
            raise Exception(f"GPU index {device_index} is out of range. Only {len(lines)} GPUs found.")
            
        # Just extract the device name from the line
        device_name = lines[device_index].split(':')[1].split('(')[0].strip()
        return device_name
        
    except Exception as e:
        print(f"Error getting GPU info: {str(e)}")
        return None

def load_config() -> dict:
    """Load and return configuration from config.json."""
    with open('config.json', 'r') as f:
        return json.load(f)

def print_device_info(device_type: str, config: dict) -> None:
    """Print information about the selected device."""
    if device_type == 'gpu':
        docker_device_id = config['gpu_tests']['device_id']
        device_name = get_docker_gpu_pci_id(docker_device_id)
        if device_name is None:
            print(f"Error: Could not determine GPU name for Docker device {docker_device_id}")
            sys.exit(1)
        
        docker_image = config['gpu_tests']['docker_image']
        architecture = docker_image.split('sm_')[-1] if 'sm_' in docker_image else 'unknown'
        
        print(f"\nSelected GPU Information:")
        print(f"Device ID: {docker_device_id}")
        print(f"Device Name: {device_name}")
        print(f"Architecture: sm_{architecture}")
    else:
        print(f"\nCPU Information:")
        print(f"Docker Image: {config['cpu_tests']['docker_image']}")

def load_performance_data(results_path: Path) -> Tuple[List[float], List[float], int]:
    """Load and process performance data from CSV file."""
    search_areas = []
    durations = []
    failed_tests = 0

    with open(results_path, 'r') as file:
        reader = csv.reader(file)
        next(reader)  # Skip header
        for row in reader:
            search_area = float(row[6])
            if search_area == 0:
                continue
            if row[4].lower() == 'false':
                failed_tests += 1
            durations.append(float(row[3]))    
            search_areas.append(search_area)

    return search_areas, durations, failed_tests

def fit_linear_model(search_areas: List[float], durations: List[float]) -> Tuple[LinearRegression, float]:
    """Fit linear regression model to the data."""
    x = np.array(search_areas).reshape(-1, 1)
    y = np.array(durations)
    
    model = LinearRegression()
    model.fit(x, y)
    r2_score = model.score(x, y)
    
    return model, r2_score

def plot_results(search_areas: List[float], durations: List[float], 
                model: LinearRegression, r2_score: float) -> None:
    """Generate and display the results plot."""
    x = np.array(search_areas).reshape(-1, 1)
    y_pred = model.predict(x)
    
    plt.figure(figsize=(10, 6))
    plt.scatter(x, durations, color='blue', label='Original points')
    plt.plot(x, y_pred, color='red', 
            label=f'Linear fit (y = {model.coef_[0]:.10f}x + {model.intercept_:.10f})')
    plt.xlabel('Search Area')
    plt.ylabel('Duration (seconds)')
    plt.title(f'Linear Regression: Duration vs Search Area (R² = {r2_score:.4f})')
    plt.legend()
    plt.grid(True)
    plt.show()

def main() -> None:
    """Main execution function."""
    if len(sys.argv) != 2 or sys.argv[1] not in ['gpu', 'cpu']:
        print("Usage: python fit_linear.py <device_type>")
        print("device_type must be 'gpu' or 'cpu'")
        sys.exit(1)

    device_type = sys.argv[1]
    results_dir = Path(f'{device_type}_results')
    
    # Combine results first
    combined_df = combine_temp_results(device_type)
    if combined_df is None:
        print("Error: Failed to combine results")
        sys.exit(1)
    
    config = load_config()
    print_device_info(device_type, config)
    
    # Load and process data
    search_areas, durations, failed_tests = load_performance_data(results_dir / "tmp_result.csv")
    
    if failed_tests > 0:
        print(f"Warning: Dataset contains {failed_tests} failed test(s)")
    else:
        print("All tests were successful")
    
    # Fit model and calculate metrics
    model, r2_score = fit_linear_model(search_areas, durations)
    
    # Print results
    print("\nPerformance equation: time = penalty * search_area + bias")
    print(f"where: penalty = {model.coef_[0]:.16f}")
    print(f"       search_area: from {min(search_areas)} to {max(search_areas)}")
    print(f"       bias = {model.intercept_:.16f}")
    print(f"\nThe time for search_area = {max(search_areas)} is "
          f"{model.coef_[0] * max(search_areas) + model.intercept_} seconds")
    
    # Plot results
    plot_results(search_areas, durations, model, r2_score)
    
    print(f"Linear equation: time = {model.coef_[0]:.10f} * search_area + {model.intercept_:.10f}")
    print(f"R-squared precision score: {r2_score:.10f}")

if __name__ == "__main__":
    main()

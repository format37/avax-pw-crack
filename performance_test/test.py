import os
import json
import subprocess
import sys
from pathlib import Path
import pandas as pd
from datetime import datetime
from p_chain_tools import id_to_word, restore_p_chain_address
from cuda_config import calculate_cuda_config

class TestRunner:
    def __init__(self, config_path, test_type):
        with open(config_path) as f:
            self.config = json.load(f)[f"{test_type}_tests"]
        with open(config_path) as f:
            self.config["search_area"] = json.load(f)["search_area"]
        
        self.test_type = test_type
        self.output_dir = Path(self.config["output_dir"])
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
    def generate_config(self, mnemonic, search_area):
        """Generate config.json for a specific test"""
        cuda = calculate_cuda_config(search_area)
        end_passphrase = id_to_word(search_area)
        p_chain_address = restore_p_chain_address(mnemonic, end_passphrase)
        print(f"[{search_area}:{end_passphrase}] p-chain: {p_chain_address}")
        config = {
            "mnemonic": mnemonic,
            "start_passphrase": "a",
            "end_passphrase": end_passphrase,
            "p_chain_address": p_chain_address,
            "cuda": cuda
        }
        
        config_path = self.output_dir / "config.json"
        with open(config_path, "w") as f:
            json.dump(config, f, indent=2)
        
        return p_chain_address

    def run_docker_test(self, expected_p_chain_address):
        """Run a single test using Docker"""
        cmd = [
            "sudo",
            "docker",
            "run",
            "--rm",  # Remove container after completion
        ]
        
        # Add GPU parameters if needed
        if self.test_type == "gpu":
            cmd.extend(["--gpus", "all"])
        
        # Add volume mount and image name
        print(f">> config: {self.output_dir.absolute()}/config.json")
        print(f">> result: {self.output_dir.absolute()}/result.txt")
        cmd.extend([
            # "--cpus=1",
            # "--cpuset-cpus=0",
            # "-e", "OMP_NUM_THREADS=1",
            "-v", f"{self.output_dir.absolute()}/config.json:/config.json:ro",
            "-v", f"{self.output_dir.absolute()}/result.txt:/app/result.txt",
            "-v", f"{self.output_dir.absolute()}/time.txt:/app/time.txt",
            self.config["docker_image"]
        ])

        print(f'# Running command: {" ".join(cmd)}')
        
        # Execute and capture output
        start_time = datetime.now()
        result = subprocess.run(
            cmd, 
            capture_output=True, 
            text=True,
            env=dict(os.environ, SUDO_ASKPASS='/usr/bin/ssh-askpass')
            )
        end_time = datetime.now()

        print(f"result.returncode: {result.returncode}")
        print(f"result.stderr: {result.stderr}")
        print(f"result.stdout: {result.stdout}")

        # Read duration from {self.output_dir.absolute()}/time.txt
        with open(f"{self.output_dir.absolute()}/time.txt") as f:
            duration = float(f.read())

        # Compare {self.output_dir.absolute()}/result.txt with p_chain_address
        with open(f"{self.output_dir.absolute()}/result.txt") as f:
            result_p_chain_address = f.read().strip()
        # Extract word from second line of result
        result_word = result_p_chain_address.split('\n')[1]
        # Extract first line from result
        result_p_chain_address = result_p_chain_address.split('\n')[0]
        result_p_chain_address = result_p_chain_address.replace("Address: ", "")
        success = result_p_chain_address == expected_p_chain_address
        if not success:
            print("Test failed!")
            print(f'Expected: "{expected_p_chain_address}"')
            print(f'Actual: "{result_p_chain_address}"')
        
        return {
            "success": success,
            "output": result.stdout,
            "error": result.stderr,
            # "duration": (end_time - start_time).total_seconds()
            "duration": duration
        }

    def run_all_tests(self):
        """Run all tests based on configuration"""
        results = []
        search_config = self.config["search_area"]

        # Create self.output_dir / f"tmp" directory if it doesn't exist
        tmp_dir = self.output_dir / "tmp"
        tmp_dir.mkdir(parents=True, exist_ok=True)
        
        for search_area in range(search_config["start"], 
                               search_config["end"] + 1, 
                               search_config["step"]):
            print(f"Running test with search_area: {search_area}")
            
            # Generate config for this test
            expected_p_chain_address = self.generate_config(search_config["mnemonic"], search_area)
            
            # Run test
            result = self.run_docker_test(expected_p_chain_address)
            
            # Collect results
            results.append({
                "search_area": search_area,
                "duration": result["duration"],
                "success": result["success"]
            })
            
            # Save individual test report
            df = pd.DataFrame([results[-1]])
            df.to_csv(self.output_dir / f"tmp/report_{search_area}.csv", index=False)
        
        # Generate combined report
        df = pd.DataFrame(results)
        df.to_csv(self.output_dir / f"report_{self.test_type}.csv", index=False)
        results = []
        return results

if __name__ == "__main__":
    debug = False
    if debug:
        test_type = "cpu"
    else:
        if len(sys.argv) != 2:
            print("Usage: python test_runner.py <cpu|gpu>")
            sys.exit(1)
        test_type = sys.argv[1]
    
    config_path = "config.json"
    
    if test_type not in ["cpu", "gpu"]:
        print("Test type must be either 'cpu' or 'gpu'")
        sys.exit(1)
    
    runner = TestRunner(config_path, test_type)
    results = runner.run_all_tests()
    print(f"Completed {test_type} tests. Results saved in {runner.output_dir}")
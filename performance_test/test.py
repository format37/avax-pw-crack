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
            config_data = json.load(f)
            self.config = config_data[f"{test_type}_tests"]
            self.search_config = config_data["search_area"]
            self.alphabet = self.search_config.get("alphabet")
        
        self.test_type = test_type
        self.output_dir = Path(self.config["output_dir"])
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
    def generate_config(self, mnemonic, start_word, end_word):
        """Generate config.json for a specific test"""
        cuda = calculate_cuda_config(self.search_config["end"])  # Using max search area for CUDA config
        p_chain_address = restore_p_chain_address(mnemonic, end_word)
        print(f"[{end_word}] p-chain: {p_chain_address}")
        
        config = {
            "mnemonic": mnemonic,
            "start_passphrase": start_word,
            "end_passphrase": end_word,
            "p_chain_address": p_chain_address,
            "cuda": cuda,
            "alphabet": self.alphabet
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
            "--rm",
        ]
        
        if self.test_type == "gpu":
            device_id = self.config.get("device_id", 0)  # Get device_id from config, default to 0
            cmd.extend(["--gpus", f'"device={device_id}"'])
        
        print(f">> config: {self.output_dir.absolute()}/config.json")
        cmd.extend([
            "-v", f"{self.output_dir.absolute()}/config.json:/config.json:ro",
            "-v", f"{self.output_dir.absolute()}:/app/results",
            self.config["docker_image"]
        ])

        print(f'# Running command: {" ".join(cmd)}')
        
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

        # Extract results filename from stdout
        result_file = None
        for line in result.stdout.split('\n'):
            if 'Results saved to' in line:
                result_file = line.split('/')[-1].strip()
                break

        # Use the extracted filename to read results
        results_dir = f"{self.output_dir.absolute()}"
        if result_file:
            with open(f"{results_dir}/{result_file}") as f:
                result_content = f.read().strip()
            result_word = result_content.split('\n')[1]
            result_p_chain_address = result_content.split('\n')[0]
            result_p_chain_address = result_p_chain_address.replace("Address: ", "")
        else:
            print("Warning: Could not find results file in stdout")
            result_word = ""
            result_p_chain_address = ""

        # Extract execution time from the last line containing it
        duration = 0.0
        for line in reversed(result.stdout.split('\n')):
            if 'Execution time:' in line:
                try:
                    duration = float(line.split(':')[1].replace('seconds', '').strip())
                    break
                except (ValueError, IndexError):
                    print("Warning: Could not parse execution time from output")

        success = result_p_chain_address == expected_p_chain_address
        if not success:
            print("Test failed!")
            print(f'Expected: "{expected_p_chain_address}"')
            print(f'Actual: "{result_p_chain_address}"')
        
        return {
            "success": success,
            "output": result.stdout,
            "error": result.stderr,
            "duration": duration,
            "word": result_word
        }

    def id_to_word(self, alphabet, n):
        base = len(alphabet)
        result = []
        n += 1  # Adjust for 1-based indexing
        while n > 0:
            n -= 1  # Adjust for 0-based indexing
            result.append(alphabet[n % base])
            n //= base
        
        return ''.join(reversed(result))
    
    def run_all_tests(self):
        """Run all tests based on configuration"""
        results = []
        tmp_dir = self.output_dir / "tmp"
        tmp_dir.mkdir(parents=True, exist_ok=True)
        
        start_passphrase = self.id_to_word(
            self.search_config["alphabet"], 
            self.search_config["start"]
            )
        test_count = 0
        for end_id in range(
            self.search_config["start"], 
            self.search_config["end"], 
            self.search_config["step"]
            ):
            end_passphrase = self.id_to_word(self.search_config["alphabet"], end_id)
            
            # Generate config for this test
            expected_p_chain_address = self.generate_config(
                self.search_config["mnemonic"],
                start_passphrase,
                end_passphrase,
            )
            
            # Run test
            result = self.run_docker_test(expected_p_chain_address)
            
            # Collect results
            results.append({
                "test_number": test_count,
                "start_word": start_passphrase,
                "end_word": end_passphrase,
                "duration": result["duration"],
                "success": result["success"],
                "found_word": result["word"]
            })
            
            # Save individual test report
            df = pd.DataFrame([results[-1]])
            df.to_csv(self.output_dir / f"tmp/report_{test_count}.csv", index=False)
            
            test_count += 1

        # Calculate and print search area size
        search_area_size = self.search_config["end"] - self.search_config["start"]
        print(f"Search area size: {search_area_size} words")
        # Calculate and print penalty size (time per word searched)
        penalty = result["duration"] / search_area_size
        print(f"Performance penalty score: {penalty:.20f}")
        
        # Generate combined report
        df = pd.DataFrame(results)
        df.to_csv(self.output_dir / f"report_{self.test_type}.csv", index=False)
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

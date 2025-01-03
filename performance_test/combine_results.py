import pandas as pd
import glob
from pathlib import Path
import sys

def combine_temp_results(device_type):
    """
    Combine all temporary result files for a specific device type into a single CSV file.
    
    Args:
        device_type (str): Either 'cpu' or 'gpu'
    """
    results_dir = Path(f"{device_type}_results")
    tmp_dir = results_dir / "tmp"
    
    if not tmp_dir.exists():
        print(f"Error: Directory {tmp_dir} does not exist")
        return
    
    all_reports = []
    
    # Get all report files and sort them by modification time (newest first)
    report_files = [(f, f.stat().st_mtime) for f in tmp_dir.glob("report_*.csv")]
    report_files.sort(key=lambda x: x[1], reverse=True)
    
    # Process files until we find report_0.csv
    for file_path, _ in report_files:
        try:
            if file_path.name == 'report_0.csv':
                df = pd.read_csv(file_path)
                all_reports.append(df)
                print(f"Read {file_path}")
                break
                
            df = pd.read_csv(file_path)
            all_reports.append(df)
            print(f"Read {file_path}")
        except Exception as e:
            print(f"Error reading {file_path}: {e}")
    
    if all_reports:
        # Reverse the list to maintain chronological order (oldest to newest)
        all_reports.reverse()
        
        # Combine all reports into a single DataFrame
        combined_df = pd.concat(all_reports, ignore_index=True)
        
        # Save the combined results
        output_path = results_dir / "tmp_result.csv"
        combined_df.to_csv(output_path, index=False)
        print(f"Combined results saved to {output_path}")
        return combined_df
    else:
        print("No report files found")
        return None

if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in ['cpu', 'gpu']:
        print("Usage: python combine_results.py <cpu|gpu>")
        sys.exit(1)
    
    device_type = sys.argv[1]
    combine_temp_results(device_type) 
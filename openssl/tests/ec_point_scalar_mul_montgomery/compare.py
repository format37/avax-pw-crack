import pandas as pd
import re

def extract_bits(filename):
    data = []
    pbit_pattern = r'<< i: (\d+), pbit: (\d+)'
    kbit_pattern = r'>> i: (\d+), kbit: (\d+)'
    
    with open(filename, 'r') as file:
        for line in file:
            if '<< i:' in line:
                match = re.search(pbit_pattern, line)
                if match:
                    i = int(match.group(1))
                    pbit = int(match.group(2))
                    # Find or update existing entry
                    existing = next((item for item in data if item['i'] == i), None)
                    if existing:
                        existing['pbit'] = pbit
                    else:
                        data.append({'i': i, 'pbit': pbit, 'kbit': None})
            
            elif '>> i:' in line:
                match = re.search(kbit_pattern, line)
                if match:
                    i = int(match.group(1))
                    kbit = int(match.group(2))
                    # Find or update existing entry
                    existing = next((item for item in data if item['i'] == i), None)
                    if existing:
                        existing['kbit'] = kbit
                    else:
                        data.append({'i': i, 'pbit': None, 'kbit': kbit})
    
    return pd.DataFrame(data)

def compare_log_files(ossl_file, cuda_file):
    # Read and process both files
    df_ossl = extract_bits(ossl_file)
    df_cuda = extract_bits(cuda_file)
    
    # Merge dataframes on 'i' column
    df_merged = pd.merge(
        df_ossl, 
        df_cuda, 
        on='i', 
        suffixes=('_ossl', '_cuda'),
        how='outer'
    )
    
    # Find differences in pbit values
    pbit_diff = df_merged[
        (df_merged['pbit_ossl'] != df_merged['pbit_cuda']) & 
        (df_merged['pbit_ossl'].notna()) & 
        (df_merged['pbit_cuda'].notna())
    ]
    
    # Find differences in kbit values
    kbit_diff = df_merged[
        (df_merged['kbit_ossl'] != df_merged['kbit_cuda']) & 
        (df_merged['kbit_ossl'].notna()) & 
        (df_merged['kbit_cuda'].notna())
    ]
    
    if pbit_diff.empty and kbit_diff.empty:
        print("No differences found in bit values")
    else:
        if not pbit_diff.empty:
            print("\nFound differences in pbit values:")
            print(pbit_diff[['i', 'pbit_ossl', 'pbit_cuda']].sort_values('i'))
        
        if not kbit_diff.empty:
            print("\nFound differences in kbit values:")
            print(kbit_diff[['i', 'kbit_ossl', 'kbit_cuda']].sort_values('i'))

# Usage
if __name__ == "__main__":
    ossl_file = "run.log"
    cuda_file = "/home/alex/projects/avax-pw-crack/cuda/tests/ec_point_scalar_mul_montgomery/run.log"
    compare_log_files(ossl_file, cuda_file)
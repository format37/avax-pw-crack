import os
import filecmp

def compare_files_in_directories(path_0, path_1):
    # Initialize counters
    identical_files_count = 0
    non_identical_files_count = 0
    
    # List the files in each directory
    files_0 = sorted([f for f in os.listdir(path_0) if f.startswith("computed_addresses")])
    files_1 = sorted([f for f in os.listdir(path_1) if f.startswith("computed_addresses")])
    
    # Check if the number of files in both directories are the same
    if len(files_0) != len(files_1):
        print("The number of files in the two directories are not the same!")
        return
    
    # Loop through each pair of files and compare them
    for f0, f1 in zip(files_0, files_1):
        file_0_path = os.path.join(path_0, f0)
        file_1_path = os.path.join(path_1, f1)
        
        if filecmp.cmp(file_0_path, file_1_path):
            identical_files_count += 1
        else:
            non_identical_files_count += 1
            print(f"Files {file_0_path} and {file_1_path} are not identical!")
    
    # Print report
    print(f"Total number of files compared: {identical_files_count + non_identical_files_count}")
    print(f"Number of identical files: {identical_files_count}")
    print(f"Number of non-identical files: {non_identical_files_count}")

# Uncomment the next line to run the function with your actual directories
compare_files_in_directories("data_0/", "data_1/")

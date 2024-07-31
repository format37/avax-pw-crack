import csv
from collections import defaultdict

# Reference values as integers
REFERENCE_VALUES = {
    "Public Key X": 0x66c1981565aedcc419cc56e72954e62fa0c3f43955b99a6a835afa2f29a7a7b6,
    "Public Key Y": 0x49F4AA5706A41B7F0F26CB03375787701556E5F3B9D7F6DD53BEFD80DCFECD8F
}

def check_results(filename):
    results = defaultdict(list)
    
    # Read the CSV file
    with open(filename, 'r') as f:
        reader = csv.reader(f)
        next(reader)  # Skip the header row
        for row in reader:
            thread, key, value = row
            # Convert hex string to integer, ignoring leading zeros
            results[key].append(int(value, 16))
    
    # Check if all values for each key are the same
    all_same = True
    for key, values in results.items():
        if len(set(values)) != 1:
            print(f"Mismatch found for {key}")
            all_same = False
        else:
            print(f"{key}: All {len(values)} threads have the same value")
        
        # Check against reference value if available
        if key in REFERENCE_VALUES:
            reference = REFERENCE_VALUES[key]
            if values[0] == reference:
                print(f"{key}: Matches the reference value: OK")
            else:
                print(f"{key}: Does NOT match the reference value")
                print(f"  Expected: {reference:064x}")
                print(f"  Got:      {values[0]:064x}")
                all_same = False

    if all_same:
        print("\nAll results are identical across all threads and match the reference values!")
    else:
        print("\nSome results differ between threads or don't match the reference values.")

    # Optional: Print the first few values for each key
    for key, values in results.items():
        print(f"\nFirst few values for {key}:")
        for i, value in enumerate(values[:5]):  # Print first 5 values
            print(f"  Thread {i}: {value:064x}")
        if len(values) > 5:
            print("  ...")

if __name__ == "__main__":
    check_results("all_results.csv")
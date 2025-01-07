import pandas as pd

def check_variant_id_consistency(filepath):
    """
    Check the consistency of VariantId column in a CSV file.
    
    Args:
        filepath (str): Path to the CSV file
        
    Returns:
        tuple: (bool, str) - (is_consistent, detailed_message)
    """
    # try:
    
    # Read the TSV file
    df = pd.read_csv(filepath, sep='\t', quoting=3)  # quoting=3 means QUOTE_NONE
    
    # Verify that VariantId column exists
    if 'VariantId' not in df.columns:
        return False, "Error: VariantId column not found in the CSV file"
    
    # Get all variant IDs and sort them
    variant_ids = sorted(df['VariantId'].unique())
    
    # Get first and last IDs
    first_id = min(variant_ids)
    last_id = max(variant_ids)
    
    # Calculate the expected number of IDs
    expected_count = last_id - first_id + 1
    
    # Create a set of all expected IDs
    expected_ids = set(range(first_id, last_id + 1))
    actual_ids = set(variant_ids)
    
    # Check for consistency
    is_consistent = (expected_ids == actual_ids)
    
    # Prepare detailed message
    details = (
        f"First ID: {first_id}\n"
        f"Last ID: {last_id}\n"
        f"Expected count: {expected_count}\n"
        f"Actual count: {len(variant_ids)}\n"
    )
    
    if not is_consistent:
        # Find missing and duplicate values
        missing_ids = expected_ids - actual_ids
        duplicate_ids = df[df['VariantId'].duplicated()]['VariantId'].unique()
        
        if missing_ids:
            details += f"Missing IDs: {sorted(missing_ids)}\n"
        if len(duplicate_ids) > 0:
            details += f"Duplicate IDs: {sorted(duplicate_ids)}\n"
            
    return is_consistent, details
    
# except Exception as e:
#     return False, f"Error processing file: {str(e)}"

# Example usage:
# is_consistent, message = check_variant_id_consistency("your_file.csv")
# print(f"Is consistent: {is_consistent}")
# print(message)

def check_passphrase_uniqueness(df):
    """
    Check if all passphrases in the DataFrame are unique.
    
    Args:
        df (pandas.DataFrame): DataFrame containing the Passphrase column
        
    Returns:
        tuple: (bool, str) - (is_unique, detailed_message)
    """
    if 'Passphrase' not in df.columns:
        return False, "Error: Passphrase column not found in the CSV file"
    
    duplicate_passphrases = df[df['Passphrase'].duplicated()]['Passphrase'].unique()
    is_unique = len(duplicate_passphrases) == 0
    
    details = f"Total passphrases: {len(df['Passphrase'])}\n"
    if not is_unique:
        details += f"Found {len(duplicate_passphrases)} duplicate passphrase(s)\n"
        details += f"Duplicate values: {duplicate_passphrases.tolist()}"
    
    return is_unique, details

def main(filepath):
    """
    Main function to check both VariantId consistency and Passphrase uniqueness.
    
    Args:
        filepath (str): Path to the CSV file
    """
    try:
        # Read the TSV file
        df = pd.read_csv(filepath, sep='\t')
        
        # Check VariantId consistency
        variant_consistent, variant_details = check_variant_id_consistency(filepath)
        print("\n=== VariantId Consistency Check ===")
        print(f"Is consistent: {variant_consistent}")
        print(variant_details)
        
        # Check Passphrase uniqueness
        passphrase_unique, passphrase_details = check_passphrase_uniqueness(df)
        print("\n=== Passphrase Uniqueness Check ===")
        print(f"Is unique: {passphrase_unique}")
        print(passphrase_details)
        
    except Exception as e:
        print(f"Error processing file: {str(e)}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python check_p_chain_consistency.py <csv_file_path>")
        sys.exit(1)
    
    main(sys.argv[1])

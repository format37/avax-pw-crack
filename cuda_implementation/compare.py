import pandas as pd

# Load the two CSV files
file1_path = 'python.csv'
file2_path = 'cuda_with_pchain.csv'

# Load data from the CSV files
df1 = pd.read_csv(file1_path)
df2 = pd.read_csv(file2_path)

# Merge the dataframes on 'id' and 'variant' to find matches and mismatches
merged = pd.merge(df1, df2, on=['id', 'variant'], how='outer', suffixes=('_A', '_B'), indicator=True)

# Separate correct matches and discrepancies
correct = merged[merged['_merge'] == 'both']
discrepancies = merged[merged['_merge'] != 'both']

# Save the correct matches and discrepancies to CSV files
correct.to_csv('correct.csv', index=False)
discrepancies.to_csv('discrepancy.csv', index=False)

# Print a short report
print(f"Count of correct matches: {correct.shape[0]}")
print(f"Count of discrepancies: {discrepancies.shape[0]}")


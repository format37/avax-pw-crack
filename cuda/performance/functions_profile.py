
import os
import pandas as pd
import matplotlib.pyplot as plt

def plot_multiple_csv_counts(folder_path):
    # Prepare figure for plotting counts
    fig, ax = plt.subplots(figsize=(10, 6))
    
    # Go through each CSV file in the folder
    for file_name in os.listdir(folder_path):
        if file_name.endswith('.csv'):
            # Read the CSV file
            file_path = os.path.join(folder_path, file_name)
            df = pd.read_csv(file_path)
            
            # Plot the Calls data
            # ax.bar(df["FunctionName"], df["Calls"], label=file_name, alpha=0.6)
            ax.plot(df["FunctionName"], df["Calls"], marker='o', linestyle='-', label=file_name, alpha=0.6)
    
    ax.set_xlabel("Function Name")
    ax.set_ylabel("Calls")
    ax.set_title("Function Call Counts from Multiple CSV Files")
    ax.legend()
    
    plt.tight_layout()
    # Save the plot as a PNG file
    plt.savefig('function_profile_calls.png')
    plt.show()

def plot_multiple_csv_times(folder_path):
    # Prepare figure for plotting times
    fig, ax = plt.subplots(figsize=(10, 6))
    
    # Go through each CSV file in the folder
    for file_name in os.listdir(folder_path):
        if file_name.endswith('.csv'):
            # Read the CSV file
            file_path = os.path.join(folder_path, file_name)
            df = pd.read_csv(file_path)
            
            # Plot the TotalTime(cycles) data
            ax.plot(df["FunctionName"], df["TotalTime(cycles)"], marker='o', linestyle='-', label=file_name, alpha=0.6)
    
    ax.set_xlabel("Function Name")
    ax.set_ylabel("Total Time (cycles)")
    ax.set_title("Function Total Time (cycles) from Multiple CSV Files")
    ax.legend()
    
    plt.tight_layout()
    # Save the plot as a PNG file
    plt.savefig('function_profile_times.png')
    plt.show()

# Example usage:
plot_multiple_csv_counts('functions_data')
plot_multiple_csv_times('functions_data')

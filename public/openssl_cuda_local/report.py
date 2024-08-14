import matplotlib.pyplot as plt
import pandas as pd
import numpy as np

def read_last_n_lines(filename, n):
    with open(filename, 'r') as file:
        lines = file.readlines()
    # Search for the line starting from 'Function' and return the last n lines
    for i, line in enumerate(reversed(lines)):
        if line.startswith('Function'):
            break
    i+=1  # Adjusting for 0-based index
    print(f'Found header at line {len(lines) - i}: {lines[-i]}')
    return lines[-i:]

def process_data(lines):
    data = [line.strip().split(',') for line in lines if line.strip()]
    df = pd.DataFrame(data[1:], columns=data[0])  # Skip header
    df['Calls'] = df['Calls'].astype(int)
    df['TotalTime(cycles)'] = df['TotalTime(cycles)'].astype(int)
    
    # Extract testKernel time and remove it from the dataframe
    total_time = df[df['Function'] == 'testKernel']['TotalTime(cycles)'].values[0]
    df = df[df['Function'] != 'testKernel']
    
    # Calculate time for 'Others'
    accounted_time = df['TotalTime(cycles)'].sum()
    others_time = total_time - accounted_time
    
    # Add 'Others' to the dataframe
    others_df = pd.DataFrame({'Function': ['Others'], 'Calls': [1], 'TotalTime(cycles)': [others_time]})
    df = pd.concat([df, others_df], ignore_index=True)
    
    # Calculate percentages
    df['Percentage'] = df['TotalTime(cycles)'] / total_time * 100
    
    return df, total_time

def generate_report(df, total_time):
    print("Performance Report:")
    print("-" * 80)
    print(f"{'Function':<20} {'Calls':<10} {'Total Time (cycles)':<20} {'Percentage':>10}")
    print("-" * 80)
    for _, row in df.iterrows():
        print(f"{row['Function']:<20} {row['Calls']:<10} {row['TotalTime(cycles)']:<20} {row['Percentage']:>10.2f}%")
    print("-" * 80)
    print(f"{'Total':<20} {'':<10} {total_time:<20} {'100.00':>10}%")
    print("-" * 80)

def plot_comparison(df):
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 10))
    
    # Time percentage bar plot
    df_sorted = df.sort_values('Percentage', ascending=False)
    ax1.bar(df_sorted['Function'], df_sorted['Percentage'])
    ax1.set_title('Percentage of Total Time per Function')
    ax1.set_ylabel('Percentage')
    ax1.set_xticklabels(df_sorted['Function'], rotation=45, ha='right')

    # Call count bar plot (excluding 'Others')
    df_calls = df[df['Function'] != 'Others'].sort_values('Calls', ascending=False)
    ax2.bar(df_calls['Function'], df_calls['Calls'])
    ax2.set_title('Number of Calls per Function')
    ax2.set_ylabel('Calls')
    ax2.set_xticklabels(df_calls['Function'], rotation=45, ha='right')
    ax2.set_yscale('log')  # Using log scale for better visibility

    plt.tight_layout()
    plt.savefig('performance_comparison.png')
    print("Graph saved as 'performance_comparison.png'")

# Main execution
filename = 'run.log'
n_lines = 25

try:
    lines = read_last_n_lines(filename, n_lines)
    df, total_time = process_data(lines)
    generate_report(df, total_time)
    plot_comparison(df)
except FileNotFoundError:
    print(f"Error: The file '{filename}' was not found.")
except IOError:
    print(f"Error: There was an issue reading the file '{filename}'.")
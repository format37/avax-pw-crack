import pandas as pd
import matplotlib.pyplot as plt

# # Data in CSV format
# csv_data = """SearchArea,CPU_time,GPU_time
# 1,0.010281390,8.144225336
# 32768,73.595482973,86.804312257
# 65536,243.278517960,178.120320960
# """

# # Save the CSV data to a file
# with open('cpu_gpu_comparison/data.csv', 'w') as file:
#     file.write(csv_data)

# Load data from the CSV file
df = pd.read_csv('cpu_gpu_comparison/data.csv')

# Plot the data
plt.figure(figsize=(10, 6))
plt.plot(df['SearchArea'], df['CPU_time'], label='CPU Time', marker='o')
plt.plot(df['SearchArea'], df['GPU_time'], label='GPU Time', marker='o')

# Labeling
plt.xlabel('Search Area')
plt.ylabel('Time (seconds)')
plt.title('CPU vs GPU Time Comparison')
plt.legend()
plt.grid(True)

# Save the plot to a file
plt.savefig('cpu_gpu_comparison.png')

# Display the plot
plt.show()
import re
from collections import defaultdict

function_stats = defaultdict(lambda: {'calls': 0, 'times': []})

with open('run.log', 'r') as f:
    for line in f:
        match = re.match(r'Function: (\w+), Call: (\d+), Time: ([\d.]+)', line)
        if match:
            func_name, call, time = match.groups()
            function_stats[func_name]['calls'] = max(function_stats[func_name]['calls'], int(call))
            function_stats[func_name]['times'].append(float(time))

# Calculate total time of main function
main_total_time = sum(function_stats['main']['times'])

# Sort functions by total time (descending order)
sorted_functions = sorted(function_stats.items(), key=lambda x: sum(x[1]['times']), reverse=True)

for func, stats in sorted_functions:
    times = stats['times']
    total_time = sum(times)
    percentage = (total_time / main_total_time) * 100 if func != 'main' else 100.0

    print(f"{func}:")
    print(f"  Calls: {stats['calls']}")
    print(f"  Total Time: {total_time:.6f}")
    print(f"  Percentage of Main: {percentage:.2f}%")
    print(f"  Mean Time: {total_time/len(times):.6f}")
    print(f"  Min Time: {min(times):.6f}")
    print(f"  Max Time: {max(times):.6f}")
    if len(times) > 1:
        median = sorted(times)[len(times)//2]
        print(f"  Median Time: {median:.6f}")
    print()

# Print summary of top time-consuming functions
print("Top 5 time-consuming functions:")
for func, stats in sorted_functions[:5]:
    if func != 'main':
        total_time = sum(stats['times'])
        percentage = (total_time / main_total_time) * 100
        print(f"{func}: {percentage:.2f}% of main time")
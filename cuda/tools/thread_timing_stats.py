import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
from scipy import stats

# Read the CSV file
df = pd.read_csv('thread_timing.csv')

# Calculate additional metrics
df['StartTimeRelative'] = df['StartTime'] - df['StartTime'].min()
df['EndTimeRelative'] = df['EndTime'] - df['StartTime'].min()
df['StartTimeMs'] = df['StartTimeRelative'] / 1e6  # Convert to milliseconds
df['EndTimeMs'] = df['EndTimeRelative'] / 1e6  # Convert to milliseconds
df['DurationMs'] = df['Duration'] / 1e6  # Convert to millisecond

# 1. Histogram of thread start times
plt.figure(figsize=(12, 6))
plt.hist(df['StartTimeMs'], bins=100, edgecolor='black')
plt.title('Histogram of Thread Start Times')
plt.xlabel('Start Time (ms)')
plt.ylabel('Frequency')
plt.savefig('start_time_histogram.png')
plt.close()

# 2. Histogram of thread durations
plt.figure(figsize=(12, 6))
plt.hist(df['DurationMs'], bins=100, edgecolor='black')
plt.title('Histogram of Thread Durations')
plt.xlabel('Duration (ms)')
plt.ylabel('Frequency')
plt.savefig('duration_histogram.png')
plt.close()

# 3. Scatter plot of start time vs duration
plt.figure(figsize=(12, 6))
plt.scatter(df['StartTimeMs'], df['DurationMs'], alpha=0.1)
plt.title('Start Time vs Duration')
plt.xlabel('Start Time (ms)')
plt.ylabel('Duration (ms)')
plt.savefig('start_time_vs_duration.png')
plt.close()

# 4. Box plot of durations by block
plt.figure(figsize=(20, 6))
sns.boxplot(x='BlockIdx', y='DurationMs', data=df)
plt.title('Distribution of Thread Durations by Block')
plt.xlabel('Block ID')
plt.ylabel('Duration (ms)')
plt.xticks(rotation=90)
plt.savefig('duration_by_block.png', bbox_inches='tight')
plt.close()

# 5. Heatmap of start times
plt.figure(figsize=(12, 8))
start_times_pivot = df.pivot(index='BlockIdx', columns='ThreadIdx', values='StartTimeMs')
sns.heatmap(start_times_pivot, cmap='viridis')
plt.title('Heatmap of Thread Start Times')
plt.xlabel('Thread ID within Block')
plt.ylabel('Block ID')
plt.savefig('start_time_heatmap.png')
plt.close()

# 6. Heatmap of durations
plt.figure(figsize=(12, 8))
durations_pivot = df.pivot(index='BlockIdx', columns='ThreadIdx', values='DurationMs')
sns.heatmap(durations_pivot, cmap='viridis')
plt.title('Heatmap of Thread Durations')
plt.xlabel('Thread ID within Block')
plt.ylabel('Block ID')
plt.savefig('duration_heatmap.png')
plt.close()

# Additional visualization: Scatter plot of durations by block and thread
plt.figure(figsize=(12, 8))
scatter = plt.scatter(df['BlockIdx'], df['ThreadIdx'], c=df['DurationMs'], cmap='viridis', alpha=0.5)
plt.colorbar(scatter, label='Duration (ms)')
plt.title('Thread Durations by Block and Thread ID')
plt.xlabel('Block ID')
plt.ylabel('Thread ID within Block')
plt.savefig('duration_scatter.png')
plt.close()

# Additional visualization: 3D surface plot of durations
from mpl_toolkits.mplot3d import Axes3D

fig = plt.figure(figsize=(12, 8))
ax = fig.add_subplot(111, projection='3d')
surf = ax.plot_trisurf(df['BlockIdx'], df['ThreadIdx'], df['DurationMs'], cmap='viridis', edgecolor='none')
ax.set_xlabel('Block ID')
ax.set_ylabel('Thread ID within Block')
ax.set_zlabel('Duration (ms)')
ax.set_title('3D Surface Plot of Thread Durations')
fig.colorbar(surf, ax=ax, shrink=0.5, aspect=5)
plt.savefig('duration_3d_surface.png')
plt.close()

# Calculate and print summary statistics
print("Summary Statistics:")
print(df[['StartTimeMs', 'EndTimeMs', 'DurationMs']].describe())

print("\nTop 10 longest running threads:")
print(df.nlargest(10, 'DurationMs')[['ThreadIdx', 'BlockIdx', 'StartTimeMs', 'DurationMs']])

print("\nTop 10 latest starting threads:")
print(df.nlargest(10, 'StartTimeMs')[['ThreadIdx', 'BlockIdx', 'StartTimeMs', 'DurationMs']])

# Calculate and print correlation coefficients
correlation_matrix = df[['StartTimeMs', 'DurationMs']].corr()
print("\nCorrelation between Start Time and Duration:")
print(correlation_matrix)

# Perform statistical tests
start_time_normality = stats.normaltest(df['StartTimeMs'])
duration_normality = stats.normaltest(df['DurationMs'])

print("\nNormality test for Start Times (p-value):", start_time_normality.pvalue)
print("Normality test for Durations (p-value):", duration_normality.pvalue)

# Save summary statistics to a file
with open('summary_statistics.txt', 'w') as f:
    f.write("Summary Statistics:\n")
    f.write(df[['StartTimeMs', 'EndTimeMs', 'DurationMs']].describe().to_string())
    f.write("\n\nTop 10 longest running threads:\n")
    f.write(df.nlargest(10, 'DurationMs')[['ThreadIdx', 'BlockIdx', 'StartTimeMs', 'DurationMs']].to_string())
    f.write("\n\nTop 10 latest starting threads:\n")
    f.write(df.nlargest(10, 'StartTimeMs')[['ThreadIdx', 'BlockIdx', 'StartTimeMs', 'DurationMs']].to_string())
    f.write("\n\nCorrelation between Start Time and Duration:\n")
    f.write(correlation_matrix.to_string())
    f.write(f"\n\nNormality test for Start Times (p-value): {start_time_normality.pvalue}")
    f.write(f"\nNormality test for Durations (p-value): {duration_normality.pvalue}")

print("[0] Analysis complete. Check the generated image files and summary_statistics.txt for results.")

def generate_statistical_report(df):
    early_threads = df[df['StartTimeMs'] < df['StartTimeMs'].quantile(0.25)]
    late_threads = df[df['StartTimeMs'] > df['StartTimeMs'].quantile(0.75)]
    
    report = """
    Statistical Report on Thread Timing:

    1. Thread Count and Distribution:
       - Total threads: {total_threads}
       - Total blocks: {total_blocks}
       - Threads per block: {threads_per_block}
       - Threads starting in first 25% of time range: {early_threads} ({early_threads_pct:.2f}%)
       - Threads starting in last 25% of time range: {late_threads} ({late_threads_pct:.2f}%)

    2. Start Time Statistics (ms):
       - Min: {start_min:.2f}
       - Max: {start_max:.2f}
       - Mean: {start_mean:.2f}
       - Median: {start_median:.2f}
       - Standard Deviation: {start_std:.2f}

    3. Duration Statistics (ms):
       - Min: {dur_min:.2f}
       - Max: {dur_max:.2f}
       - Mean: {dur_mean:.2f}
       - Median: {dur_median:.2f}
       - Standard Deviation: {dur_std:.2f}

    4. Duration Comparison:
       - Early threads (first 25%) mean duration: {early_dur_mean:.2f} ms
       - Late threads (last 25%) mean duration: {late_dur_mean:.2f} ms
       - Ratio of early to late mean duration: {dur_ratio:.2f}

    5. Correlation:
       - Correlation coefficient between start time and duration: {correlation:.4f}

    6. Block-level Statistics:
       - Blocks with longest average duration: {top_blocks}
       - Blocks with shortest average duration: {bottom_blocks}

    7. Thread-level Statistics:
       - Thread IDs with longest average duration: {top_threads}
       - Thread IDs with shortest average duration: {bottom_threads}

    8. Variability Measures:
       - Coefficient of Variation (Start Time): {cv_start:.4f}
       - Coefficient of Variation (Duration): {cv_dur:.4f}
       - Interquartile Range (Start Time): {iqr_start:.2f} ms
       - Interquartile Range (Duration): {iqr_dur:.2f} ms

    9. Extreme Values:
       - Top 5 longest durations (ms): {top_durations}
       - Top 5 latest start times (ms): {top_start_times}
    """.format(
        total_threads=len(df),
        total_blocks=df['BlockIdx'].nunique(),
        threads_per_block=df.groupby('BlockIdx').size().iloc[0],
        early_threads=len(early_threads),
        early_threads_pct=len(early_threads) / len(df) * 100,
        late_threads=len(late_threads),
        late_threads_pct=len(late_threads) / len(df) * 100,
        start_min=df['StartTimeMs'].min(),
        start_max=df['StartTimeMs'].max(),
        start_mean=df['StartTimeMs'].mean(),
        start_median=df['StartTimeMs'].median(),
        start_std=df['StartTimeMs'].std(),
        dur_min=df['DurationMs'].min(),
        dur_max=df['DurationMs'].max(),
        dur_mean=df['DurationMs'].mean(),
        dur_median=df['DurationMs'].median(),
        dur_std=df['DurationMs'].std(),
        early_dur_mean=early_threads['DurationMs'].mean(),
        late_dur_mean=late_threads['DurationMs'].mean(),
        dur_ratio=early_threads['DurationMs'].mean() / late_threads['DurationMs'].mean(),
        correlation=df['StartTimeMs'].corr(df['DurationMs']),
        top_blocks=', '.join(map(str, df.groupby('BlockIdx')['DurationMs'].mean().nlargest(5).index.tolist())),
        bottom_blocks=', '.join(map(str, df.groupby('BlockIdx')['DurationMs'].mean().nsmallest(5).index.tolist())),
        top_threads=', '.join(map(str, df.groupby('ThreadIdx')['DurationMs'].mean().nlargest(5).index.tolist())),
        bottom_threads=', '.join(map(str, df.groupby('ThreadIdx')['DurationMs'].mean().nsmallest(5).index.tolist())),
        cv_start=df['StartTimeMs'].std() / df['StartTimeMs'].mean(),
        cv_dur=df['DurationMs'].std() / df['DurationMs'].mean(),
        iqr_start=df['StartTimeMs'].quantile(0.75) - df['StartTimeMs'].quantile(0.25),
        iqr_dur=df['DurationMs'].quantile(0.75) - df['DurationMs'].quantile(0.25),
        top_durations=', '.join(map(str, df['DurationMs'].nlargest(5).tolist())),
        top_start_times=', '.join(map(str, df['StartTimeMs'].nlargest(5).tolist()))
    )
    
    return report

# Generate and save the report
statistical_report = generate_statistical_report(df)
print(statistical_report)
with open('statistical_analysis.txt', 'w') as f:
    f.write(statistical_report)

# Additional visualizations
plt.figure(figsize=(12, 8))
sns.scatterplot(data=df, x='BlockIdx', y='ThreadIdx', hue='DurationMs', palette='viridis')
plt.title('Thread Duration by Block and Thread ID')
plt.savefig('thread_duration_scatter.png')
plt.close()

plt.figure(figsize=(12, 8))
sns.boxplot(data=df, x='BlockIdx', y='DurationMs')
plt.title('Duration Distribution by Block')
plt.xticks(rotation=90)
plt.savefig('duration_by_block_boxplot.png')
plt.close()

print("[1] Statistical report generated and saved to statistical_analysis.txt.")
import os
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from pathlib import Path
import numpy as np

class PerformanceAnalyzer:
    def __init__(self, base_folders=None):
        """
        Initialize the analyzer with a list of base folders to search for report files.
        
        Args:
            base_folders (list): List of folder paths where report files are located
                               e.g., ['./gpu_results', './cpu_results', './python_results']
        """
        self.engines = ['cpu', 'gpu', 'python']
        self.base_folders = base_folders or ['.']
        self.data = {}
        
        # Set style for better-looking plots
        plt.style.use('seaborn')
        sns.set_palette("husl")
        
    def find_report_files(self):
        """Find all report files in the specified base folders."""
        report_files = {}
        
        for engine in self.engines:
            for base_folder in self.base_folders:
                file_path = Path(base_folder) / f'report_{engine}.csv'
                if file_path.exists():
                    report_files[engine] = str(file_path)
                    break  # Use the first found file for each engine
                    
        return report_files
    
    def load_data(self):
        """Load data from all available report files."""
        report_files = self.find_report_files()
        
        for engine, file_path in report_files.items():
            try:
                df = pd.read_csv(file_path)
                self.data[engine] = df
                print(f"Loaded data for {engine} engine from {file_path}")
                
                # Print basic statistics
                stats = {
                    'mean': df['duration'].mean(),
                    'min': df['duration'].min(),
                    'max': df['duration'].max(),
                    'std': df['duration'].std()
                }
                print(f"Statistics for {engine}:")
                for stat_name, value in stats.items():
                    print(f"  {stat_name}: {value:.4f}")
                print()
                
            except Exception as e:
                print(f"Error loading data for {engine}: {str(e)}")
    
    def plot_performance(self, save_path=None, figsize=(12, 8)):
        """
        Create a performance comparison plot.
        
        Args:
            save_path (str, optional): Path to save the plot image
            figsize (tuple): Figure size in inches (width, height)
        """
        if not self.data:
            print("No data loaded. Please run load_data() first.")
            return
            
        plt.figure(figsize=figsize)
        
        # Plot each engine's data
        for engine, df in self.data.items():
            plt.plot(df['search_area'], df['duration'], 
                    label=f'{engine.upper()}',
                    alpha=0.8, linewidth=2)
            
        plt.xlabel('Search Area Size', fontsize=12)
        plt.ylabel('Execution Time (seconds)', fontsize=12)
        plt.title('Performance Comparison Across Different Engines', fontsize=14, pad=20)
        
        # Add grid
        plt.grid(True, linestyle='--', alpha=0.7)
        
        # Add legend
        plt.legend(fontsize=10, bbox_to_anchor=(1.05, 1), loc='upper left')
        
        # Adjust layout to prevent label cutoff
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            print(f"Plot saved to {save_path}")
        
        plt.show()
    
    def plot_performance_with_statistics(self, save_path=None, figsize=(15, 10)):
        """
        Create a more detailed performance plot with statistical information.
        
        Args:
            save_path (str, optional): Path to save the plot image
            figsize (tuple): Figure size in inches (width, height)
        """
        if not self.data:
            print("No data loaded. Please run load_data() first.")
            return
            
        # Create figure with subplots
        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=figsize, height_ratios=[3, 1])
        
        # Plot performance lines
        for engine, df in self.data.items():
            ax1.plot(df['search_area'], df['duration'], 
                    label=f'{engine.upper()} Engine',
                    alpha=0.8, linewidth=2)
        
        ax1.set_xlabel('Search Area Size')
        ax1.set_ylabel('Execution Time (seconds)')
        ax1.set_title('Performance Comparison Across Different Engines', pad=20)
        ax1.grid(True, linestyle='--', alpha=0.7)
        ax1.legend(fontsize=10)
        
        # Create statistics table
        stats_data = []
        columns = ['Engine', 'Mean (s)', 'Min (s)', 'Max (s)', 'Std Dev']
        
        for engine, df in self.data.items():
            stats = [
                engine.upper(),
                f"{df['duration'].mean():.4f}",
                f"{df['duration'].min():.4f}",
                f"{df['duration'].max():.4f}",
                f"{df['duration'].std():.4f}"
            ]
            stats_data.append(stats)
        
        # Turn off axis for statistics table
        ax2.axis('tight')
        ax2.axis('off')
        
        # Create table
        table = ax2.table(cellText=stats_data,
                         colLabels=columns,
                         loc='center',
                         cellLoc='center',
                         colColours=['#f2f2f2']*len(columns))
        
        # Style the table
        table.auto_set_font_size(False)
        table.set_fontsize(9)
        table.scale(1.2, 1.5)
        
        # Adjust layout
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            print(f"Plot saved to {save_path}")
        
        plt.show()

# Example usage
if __name__ == "__main__":
    # Initialize analyzer with folders
    folders = ['./gpu_results']
    analyzer = PerformanceAnalyzer(folders)
    
    # Load and analyze data
    analyzer.load_data()
    
    # Create basic performance plot
    analyzer.plot_performance(save_path='performance_comparison.png')
    
    # Create detailed performance plot with statistics
    analyzer.plot_performance_with_statistics(save_path='performance_comparison_detailed.png')
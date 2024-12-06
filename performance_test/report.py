import pandas as pd

def main():
    # Read results
    cpu_results = pd.read_csv("./cpu_results/report_cpu.csv")
    gpu_results = pd.read_csv("./gpu_results/report_gpu.csv")

    # Merge and analyze
    combined = pd.merge(cpu_results, gpu_results, 
        on="search_area", 
        suffixes=('_cpu', '_gpu'))

if __name__ == "__main__":
    main()
    
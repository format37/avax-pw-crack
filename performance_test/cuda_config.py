def calculate_cuda_config(search_area):
    """
    Calculate optimal CUDA configuration prioritizing blocksPerGrid.
    
    Args:
        search_area (int): Total area to be processed
        
    Returns:
        dict: Dictionary containing threadsPerBlock and blocksPerGrid values
    """
    # Constants
    THREADS_PER_BLOCK_MAX = 256
    BLOCKS_PER_GRID_MAX = 128
    
    # Case 1: If search_area is larger than maximum capacity
    if search_area > THREADS_PER_BLOCK_MAX * BLOCKS_PER_GRID_MAX:
        return {
            "threadsPerBlock": THREADS_PER_BLOCK_MAX,
            "blocksPerGrid": BLOCKS_PER_GRID_MAX
        }
    
    # Case 2: If search_area is less than BLOCKS_PER_GRID_MAX
    if search_area <= BLOCKS_PER_GRID_MAX:
        return {
            "threadsPerBlock": 1,
            "blocksPerGrid": search_area
        }
    
    # Case 3: Calculate optimal configuration
    # Priority is to maximize blocksPerGrid
    blocks_per_grid = min(BLOCKS_PER_GRID_MAX, search_area)
    threads_per_block = (search_area + blocks_per_grid - 1) // blocks_per_grid
    
    # Ensure threadsPerBlock doesn't exceed maximum
    if threads_per_block > THREADS_PER_BLOCK_MAX:
        threads_per_block = THREADS_PER_BLOCK_MAX
        blocks_per_grid = (search_area + THREADS_PER_BLOCK_MAX - 1) // THREADS_PER_BLOCK_MAX
        blocks_per_grid = min(blocks_per_grid, BLOCKS_PER_GRID_MAX)
    
    return {
        "threadsPerBlock": threads_per_block,
        "blocksPerGrid": blocks_per_grid
    }


def main():
    # Example usage:
    test_cases = [64, 128, 1000, 130000, 1024*128+1]
    for test in test_cases:
        result = calculate_cuda_config(test)
        print(f"Search area: {test}")
        print(f"Configuration: {result}")
        print(f"Total coverage: {result['threadsPerBlock'] * result['blocksPerGrid']}")
        print("---")


if __name__ == "__main__":
    main()

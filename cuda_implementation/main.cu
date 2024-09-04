#include <cuda_runtime.h>
#include <fstream>
#include <iomanip>
#include <stdio.h>
#include <cuda.h>
#include "bignum.h"
#include "p_chain.h"

// Max threads per block: 1024
// Max blocks per grid: 2147483647
// Max total threads: 196608
#define MAX_VARIANTS 65535
#define MAX_PASSPHRASE_LENGTH 10
#define P_CHAIN_ADDRESS_LENGTH 45  // Assuming the p-chain address is 45 characters long

__device__ bool d_address_found = false;
__device__ char d_found_address[P_CHAIN_ADDRESS_LENGTH + 1];
__device__ const char alphabet[] = "abcdefghijklmnopqrstuvwxyz";
__device__ const int alphabet_length = 26;

__global__ void restore_p_chain_example(int *dummy) {
    // int thread_id = blockIdx.x * blockDim.x + threadIdx.x;
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    // for (int idx = blockIdx.x * blockDim.x + threadIdx.x; 
    //     idx < MAX_VARIANTS; 
    //     idx += blockDim.x * gridDim.x) {

        // if (idx == 32768) {
        // if (idx == 131068) {
        //if (idx == 524287) {
        if (idx == 2147482623) {
            uint8_t *mnemonic = (unsigned char *)"sell stereo useless course suffer tribe jazz monster fresh excess wire again father film sudden pelican always room attack rubber pelican trash alone cancel";
            // const char *passphrase = "avlh"; // 32768,avlh,P-avax1hs8j43549he3tuxd3wupp3nr0n9l3j80r4539a
            // const char *passphrase = "gkwb"; // 131068,gkwb,P-avax1f0ssty5xf2zys5hpctkljvjelq9lkgqgmnwtg6
            // const char *passphrase = "acunw";  // [acunw]: P-avax15t9krg3xltzxskgjxhy65kyf3q75d98q26dv0e
            const char *passphrase = "fxshqkm"; // [fxshqkm]: P-avax1fduhaad247ck2rh305c9vntxrcfrecqh6gedat
            P_CHAIN_ADDRESS_STRUCT p_chain_address = restore_p_chain_address(mnemonic, passphrase);
            printf("[%d] Restored P-chain address: %s\n", idx, p_chain_address.data);
            // printf("[%d] test\n", idx);
        }
    // }
}

int main() {
    cudaDeviceProp prop;
    cudaGetDeviceProperties(&prop, 0);

    // Maximum threads per block
    int maxThreadsPerBlock = prop.maxThreadsPerBlock;

    // Maximum blocks per grid (in x-dimension)
    int maxBlocksPerGrid = prop.maxGridSize[0];

    // Maximum total threads (limited by hardware)
    int maxTotalThreads = prop.maxThreadsPerMultiProcessor * prop.multiProcessorCount;

    printf("Device limits:\n");
    printf("Max threads per block: %d\n", maxThreadsPerBlock);
    printf("Max blocks per grid: %d\n", maxBlocksPerGrid);
    printf("Max total threads: %d\n", maxTotalThreads);

    // Calculate optimal configuration
    int threadsPerBlock = maxThreadsPerBlock;
    int blocksPerGrid = (MAX_VARIANTS + threadsPerBlock - 1) / threadsPerBlock;
    blocksPerGrid = min(blocksPerGrid, maxBlocksPerGrid);
    blocksPerGrid = min(blocksPerGrid, maxTotalThreads / threadsPerBlock);

    printf("\nOptimal configuration:\n");
    printf("Threads per block: %d\n", threadsPerBlock);
    printf("Blocks per grid: %d\n", blocksPerGrid);

    // Launch kernel
    int *d_dummy;
    cudaMalloc(&d_dummy, sizeof(int));
    // restore_p_chain_example<<<blocksPerGrid, threadsPerBlock>>>(d_dummy);
    
    // kernel<<<grid_size, threadsPerBlock, shared_mem_size, stream>>>
    // grid_size: Specifies the number of thread blocks in the grid.
    // threadsPerBlock: Specifies the number of threads in each block.
    // shared_mem_size (optional): Amount of dynamically allocated shared memory in bytes.
    // stream (optional): The CUDA stream in which the kernel should be launched.
    
    // restore_p_chain_example<<<128, 256>>>(d_dummy);
    int grid_size = maxBlocksPerGrid/threadsPerBlock;
    printf("Default kernel with %d blocks and %d threads per block. Total threads: %d\n", grid_size, threadsPerBlock, grid_size * threadsPerBlock);
    
    // Redefining according to the program memory limit
    // grid_size = 256;
    // grid_size = 512;
    // grid_size = 1024;
    // grid_size = 2048;
    // grid_size = 8192;
    // grid_size = 32768;
    // grid_size = 262144;
    // grid_size = 4194302;
    grid_size = 8388604;
    threadsPerBlock = 256;
    printf("Calling kernel with %d blocks and %d threads per block. Total threads: %d\n", grid_size, threadsPerBlock, grid_size * threadsPerBlock);
    restore_p_chain_example<<<grid_size, threadsPerBlock>>>(d_dummy);

    cudaError_t err = cudaGetLastError();
    if (err != cudaSuccess) {
        printf("Error: %s\n", cudaGetErrorString(err));
        return -1;
    }

    cudaDeviceSynchronize();
    cudaFree(d_dummy);
    cudaDeviceReset();
    return 0;
}

// int main() {
//     // const int THREADS_PER_BLOCK = 256;    
//     // int num_blocks = (MAX_VARIANTS + THREADS_PER_BLOCK - 1) / THREADS_PER_BLOCK;

//     // dim3 grid(num_blocks, 1, 1);
//     // dim3 block(THREADS_PER_BLOCK, 1, 1);

//     // Limit the number of blocks to the maximum allowed by the device
//     int maxThreadsPerBlock;
//     int maxBlocksPerGrid;
//     cudaDeviceGetAttribute(&maxThreadsPerBlock, cudaDevAttrMaxThreadsPerBlock, 0);
//     cudaDeviceGetAttribute(&maxBlocksPerGrid, cudaDevAttrMaxGridDimX, 0);

//     printf("Max threads per block: %d\n", maxThreadsPerBlock);
//     printf("Max blocks per grid: %d\n", maxBlocksPerGrid);

//     // Calculate the optimal launch configuration
//     const int THREADS_PER_BLOCK = maxThreadsPerBlock;
//     const int NUM_BLOCKS = (MAX_VARIANTS + THREADS_PER_BLOCK - 1) / THREADS_PER_BLOCK;

//     // Limit the number of blocks to the maximum allowed by the device
//     int num_blocks = min(NUM_BLOCKS, maxBlocksPerGrid);

//     printf("Launching with %d threads per block and %d blocks\n", THREADS_PER_BLOCK, num_blocks);

//     int *d_dummy;  // Dummy pointer for the kernel
//     cudaMalloc(&d_dummy, sizeof(int));

//     int minGridSize;    // Minimum grid size needed to achieve the maximum occupancy
//     int blockSize;      // Block size that achieves the best potential occupancy
//     int gridSize;       // Actual grid size to be used

//     // Get the maximum potential block size
//     cudaOccupancyMaxPotentialBlockSize(
//         &minGridSize,
//         &blockSize,
//         (void*)restore_p_chain_example,
//         0,  // dynamicSMemSize
//         MAX_VARIANTS  // blockSizeLimit
//     );

//     // Calculate the grid size
//     gridSize = (MAX_VARIANTS + blockSize - 1) / blockSize;

//     printf("Suggested block size: %d\n", blockSize);
//     printf("Minimum grid size: %d\n", minGridSize);
//     printf("Actual grid size: %d\n", gridSize);

//     // restore_p_chain_example<<<num_blocks, THREADS_PER_BLOCK>>>();
//     // restore_p_chain_example<<<num_blocks, THREADS_PER_BLOCK>>>();
//     // restore_p_chain_example<<<grid, block>>>();

//     // cudaError_t err = cudaDeviceSetLimit(cudaLimitMaxGridDimensionX, MAX_VARIANTS);
//     // if (err != cudaSuccess) {
//     //     printf("Error: %s\n", cudaGetErrorString(err));
//     //     return -1;
//     // }
    
//     // Check for errors
//     cudaError_t err = cudaGetLastError();
//     if (err != cudaSuccess) {
//         printf("Error: %s\n", cudaGetErrorString(err));
//         return -1;
//     }

    

//     cudaDeviceSynchronize();
//     cudaFree(d_dummy);
//     // Reset the device
//     cudaDeviceReset();

//     return 0;
// }
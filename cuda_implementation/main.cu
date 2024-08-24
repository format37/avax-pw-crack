#include <fstream>
#include <iomanip>
#include <stdio.h>
#include <cuda.h>
#include "bignum.h"
# include "p_chain.h"

__global__ void search_kernel() {
    int thread_id = blockIdx.x * blockDim.x + threadIdx.x;
    uint8_t *mnemonic = (unsigned char *)"sell stereo useless course suffer tribe jazz monster fresh excess wire again father film sudden pelican always room attack rubber pelican trash alone cancel";
    const char *passphrase = "TESTPHRASE";
    P_CHAIN_ADDRESS_STRUCT p_chain_address = restore_p_chain_address(mnemonic, passphrase);
    // printf("[%d] Restored P-chain address: %s\n", thread_id, p_chain_address.data);
}

int main() {
    
    // const int THREADS_PER_BLOCK = 256; // A good balance between occupancy and flexibility. Max threads per block: 1024
    // const int NUM_BLOCKS = 128; // One block per SM OK

    
    const int THREADS_PER_BLOCK = 256;
    const int NUM_BLOCKS = 512;

    // Launch kernel
    search_kernel<<<NUM_BLOCKS, THREADS_PER_BLOCK>>>();

    // Check for errors
    cudaError_t err = cudaGetLastError();
    if (err != cudaSuccess) {
        printf("Error: %s\n", cudaGetErrorString(err));
        return -1;
    }

    cudaDeviceSynchronize();
    cudaDeviceReset();
    return 0;
}
#include <fstream>
#include <iomanip>
#include <stdio.h>
#include <cuda.h>
#include "bignum.h"
# include "p_chain.h"

// #define TEST_BIGNUM_WORDS 4

__global__ void search_kernel() {
    uint8_t *mnemonic = (unsigned char *)"sell stereo useless course suffer tribe jazz monster fresh excess wire again father film sudden pelican always room attack rubber pelican trash alone cancel";
    char *passphrase = "TESTPHRASE";
    P_CHAIN_ADDRESS_STRUCT p_chain_address = restore_p_chain_address(mnemonic, passphrase);
    printf("Restored P-chain address: %s\n", p_chain_address.data);
}

int main() {
    
    const int THREADS_PER_BLOCK = 1;
    // const int THREADS_PER_BLOCK = 256; // A good balance between occupancy and flexibility
    
    const int NUM_BLOCKS = 1;
    // const int NUM_BLOCKS = 128; // One block per SM OK

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
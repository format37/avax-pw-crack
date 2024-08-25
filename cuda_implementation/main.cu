#include <fstream>
#include <iomanip>
#include <stdio.h>
#include <cuda.h>
#include "bignum.h"
# include "p_chain.h"

#define ALPHABET_SIZE 26
#define MAX_VARIANT_LENGTH 10  // Adjust this based on your needs

__device__ char int_to_char(int n) {
    return 'a' + n;
}

__device__ void find_letter_variant(int n, char* result, int* length) {
    *length = 0;
    char temp[MAX_VARIANT_LENGTH];
    
    while (n > 0 && *length < MAX_VARIANT_LENGTH) {
        n -= 1;  // Adjust for 0-based indexing
        temp[*length] = int_to_char(n % ALPHABET_SIZE);
        n /= ALPHABET_SIZE;
        (*length)++;
    }
    
    // Reverse the result
    for (int i = 0; i < *length; i++) {
        result[i] = temp[*length - 1 - i];
    }
    result[*length] = '\0';  // Null-terminate the string
}

__global__ void variant_generator_kernel(int shift) {
    int thread_id = blockIdx.x * blockDim.x + threadIdx.x;
    int variant_number = thread_id + shift;
    
    char variant[MAX_VARIANT_LENGTH + 1];
    int length;
    
    find_letter_variant(variant_number, variant, &length);
    
    printf("Thread %d (variant %d): %s\n", thread_id, variant_number, variant);
}

__global__ void search_kernel() {
    int thread_id = blockIdx.x * blockDim.x + threadIdx.x;
    uint8_t *mnemonic = (unsigned char *)"sell stereo useless course suffer tribe jazz monster fresh excess wire again father film sudden pelican always room attack rubber pelican trash alone cancel";
    const char *passphrase = "TESTPHRASE";
    P_CHAIN_ADDRESS_STRUCT p_chain_address = restore_p_chain_address(mnemonic, passphrase);
    printf("[%d] Restored P-chain address: %s\n", thread_id, p_chain_address.data);
    // May have a sense to sync threads here to handle more threads than 32786 == 256 * 128
}

int main() {
    
    const int THREADS_PER_BLOCK = 256; // A good balance between occupancy and flexibility. Max threads per block: 1024
    const int NUM_BLOCKS = 128; // One block per SM OK
    const int SHIFT = 0;  // You can change this to start from a different number

    // Launch kernel
    search_kernel<<<NUM_BLOCKS, THREADS_PER_BLOCK>>>();
    // variant_generator_kernel<<<NUM_BLOCKS, THREADS_PER_BLOCK>>>(0);

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
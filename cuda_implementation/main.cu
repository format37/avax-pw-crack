#include <fstream>
#include <iomanip>
#include <stdio.h>
#include <cuda.h>
#include "bignum.h"
#include "pbkdf2.h"

#define TEST_BIGNUM_WORDS 4

__device__ void reverse_order(BIGNUM *test_values_a) {
    for (size_t j = 0; j < TEST_BIGNUM_WORDS / 2; j++) {
        BN_ULONG temp_a = test_values_a->d[j];
        test_values_a->d[j] = test_values_a->d[TEST_BIGNUM_WORDS - 1 - j];
        test_values_a->d[TEST_BIGNUM_WORDS - 1 - j] = temp_a;
    }
}

__global__ void search_kernel() {
    printf("++ search_kernel ++\n");

    // Convert the mnemonic and passphrase to byte arrays
    uint8_t *m_mnemonic = (unsigned char *)"sell stereo useless course suffer tribe jazz monster fresh excess wire again father film sudden pelican always room attack rubber pelican trash alone cancel";
    // print as hex
    print_as_hex(m_mnemonic, 156);

    uint8_t *salt = (unsigned char *)"mnemonicTESTPHRASE";
    unsigned char derived_key[64];  // This will hold the generated seed
    // Initialize derived_key to zeros
    for (int i = 0; i < 64; ++i) {
        derived_key[i] = 0;
    }

    // Call pbkdf2_hmac to perform the key derivation
    compute_pbkdf2(
        (uint8_t *) m_mnemonic, 
        my_strlen((const char*) m_mnemonic), 
        (uint8_t *) salt, 
        my_strlen((const char*) salt),
	    2048, 
        64,
        derived_key
        );
    printf("Cuda derived_key: ");
    print_as_hex(derived_key, 64);  

    printf("-- search_kernel --\n");    
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
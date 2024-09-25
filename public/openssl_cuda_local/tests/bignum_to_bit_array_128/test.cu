// bignum_to_bit_array_test.cu

#include <stdio.h>
#include <cuda_runtime.h>
#include "bignum.h"
#include "point.h"
#include <string.h>

#define BN_ULONG_HOST unsigned long long // __int128 transferring to CUDA is not supported

#define BN_ULONG_HOST_BITS 64

#ifdef BN_128
    #define MAX_BIGNUM_SIZE_HOST (MAX_BIGNUM_SIZE * 2) // 5 * 2 = 10
#else
    #define MAX_BIGNUM_SIZE_HOST MAX_BIGNUM_SIZE // 10
#endif

__global__ void kernel_bignum_to_bit_array_test(
    BN_ULONG_HOST *bn_d, unsigned char bn_top, bool bn_neg,
    unsigned int *bits_array) {

    // Construct the BIGNUM
    BIGNUM bn;
    init_zero(&bn);

    // Copy bn_d, bn_top, bn_neg to bn
    #ifdef BN_128
        for (int i = 0; i < bn_top; ++i) {
            bn.d[i] = ((unsigned __int128)bn_d[i*2+1] << 64) | bn_d[i*2];
        }
    #else
        for (int i = 0; i < bn_top; ++i) {
            bn.d[i] = bn_d[i];
        }
    #endif
    bn.top = bn_top;
    bn.neg = bn_neg;

    // Prepare bits array
    unsigned int bits[MAX_BIT_ARRAY_SIZE];

    // Call bignum_to_bit_array
    bignum_to_bit_array(&bn, bits);

    // Copy bits back to global memory
    for (int i = 0; i < MAX_BIT_ARRAY_SIZE; ++i) {
        bits_array[i] = bits[i];
    }
}

int main() {
    #ifdef BN_128
        printf("\nBN_128\n");
    #else
        printf("\nBN_64\n");
    #endif

    // Define test BIGNUMs
    BN_ULONG_HOST test_values[][MAX_BIGNUM_SIZE_HOST] = {
        // Original test cases
        #ifdef BN_128
            // Test value 1: A small positive number
            {0x123456789ABCDEF0ULL, 0x0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL},
            // Test value 2: Maximum possible value for one BN_ULONG
            {0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL},
            // Test value 3: Zero
            {0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL},
            // Additional test cases adjusted to fit within 256 bits
            // Test value 4: Negative number
            {0x1ULL, 0x0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL},
            // Test value 5: Number with alternating bits
            {0xAAAAAAAAAAAAAAAAULL, 0xAAAAAAAAAAAAAAAAULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL},
            // Test value 6: Number with leading zeros (adjusted top)
            {0x0ULL, 0x0ULL, 0x123456789ABCDEF0ULL, 0x0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL},
        #else
            // Test value 1: A small positive number
            {0x123456789ABCDEF0ULL, 0, 0, 0, 0, 0, 0, 0, 0, 0},
            // Test value 2: Maximum possible value for two BN_ULONGs
            {0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL, 0, 0, 0, 0, 0, 0, 0, 0},
            // Test value 3: Zero
            {0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL},
            // Additional test cases adjusted to fit within 256 bits
            // Test value 4: Negative number
            {0x1ULL, 0, 0, 0, 0, 0, 0, 0, 0, 0},
            // Test value 5: Number with alternating bits
            {0xAAAAAAAAAAAAAAAAULL, 0xAAAAAAAAAAAAAAAAULL, 0, 0, 0, 0, 0, 0, 0, 0},
            // Test value 6: Number with leading zeros (adjusted top)
            {0x0ULL, 0x0ULL, 0x123456789ABCDEF0ULL, 0, 0, 0, 0, 0, 0, 0},
        #endif
        // We can omit test cases that require more than 256 bits
    };

    // Corresponding 'top' values for each test case
    #ifdef BN_128
        unsigned char test_tops[] = {1, 1, 1, 1, 1, 2};
    #else
        unsigned char test_tops[] = {1, 2, 1, 1, 2, 3};
    #endif

    // Corresponding 'neg' values (signs)
    bool test_negs[] = {0, 0, 0, 1, 0, 0};

    int num_tests = sizeof(test_values) / sizeof(test_values[0]);

    // For each test, we need to:
    for (int i = 0; i < num_tests; ++i) {
        printf("Running Test %d...\n", i);

        // Copy the test BIGNUM to device memory
        BN_ULONG_HOST *d_bn_d;
        cudaMalloc((void**)&d_bn_d, MAX_BIGNUM_SIZE_HOST * sizeof(BN_ULONG_HOST));
        cudaMemcpy(d_bn_d, test_values[i], MAX_BIGNUM_SIZE_HOST * sizeof(BN_ULONG_HOST), cudaMemcpyHostToDevice);

        // Allocate device memory for bits array
        unsigned int *d_bits_array;
        cudaMalloc((void**)&d_bits_array, MAX_BIT_ARRAY_SIZE * sizeof(unsigned int));

        // Launch the kernel
        kernel_bignum_to_bit_array_test<<<1, 1>>>(d_bn_d, test_tops[i], test_negs[i], d_bits_array);

        cudaError_t err = cudaGetLastError();
        if (err != cudaSuccess) {
            printf("Error launching kernel: %s\n", cudaGetErrorString(err));
            return -1;
        }

        cudaDeviceSynchronize();

        // Copy the bits array back to host
        unsigned int bits_array[MAX_BIT_ARRAY_SIZE];
        cudaMemcpy(bits_array, d_bits_array, MAX_BIT_ARRAY_SIZE * sizeof(unsigned int), cudaMemcpyDeviceToHost);

        // Compute expected bits array
        unsigned int expected_bits[MAX_BIT_ARRAY_SIZE] = {0};
        int index = 0;
        #ifdef BN_128
            for (int j = 0; j < test_tops[i]; ++j) {
                unsigned __int128 word = ((unsigned __int128)test_values[i][j*2+1] << 64) | test_values[i][j*2];
                for (int k = 0; k < 128 && index < MAX_BIT_ARRAY_SIZE; ++k) {
                    expected_bits[index++] = (word >> k) & 1;
                }
            }
        #else
            for (int j = 0; j < test_tops[i]; ++j) {
                BN_ULONG_HOST word = test_values[i][j];
                for (int k = 0; k < 64 && index < MAX_BIT_ARRAY_SIZE; ++k) {
                    expected_bits[index++] = (word >> k) & 1;
                }
            }
        #endif
        // Fill the rest with zeros
        while (index < MAX_BIT_ARRAY_SIZE) {
            expected_bits[index++] = 0;
        }

        // Compare bits_array and expected_bits
        bool passed = true;
        for (int k = 0; k < MAX_BIT_ARRAY_SIZE; ++k) {
            if (bits_array[k] != expected_bits[k]) {
                passed = false;
                printf("Mismatch at bit %d: expected %u, got %u\n", k, expected_bits[k], bits_array[k]);
            }
        }
        if (passed) {
            printf("Test %d passed.\n\n", i);
        } else {
            printf("Test %d failed.\n\n", i);
        }

        // Clean up device memory
        cudaFree(d_bn_d);
        cudaFree(d_bits_array);
    }

    return 0;
}

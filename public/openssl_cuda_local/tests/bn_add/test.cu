#include <stdio.h>
#include <cuda_runtime.h>
#include "bignum.h"

// Define your BIGNUM structure based on your project definitions
#define MAX_BIGNUM_WORDS 20
#define BN_ULONG unsigned long long int
#define BN_ULONG_NUM_BITS (sizeof(BN_ULONG) * 8)

// Function prototypes for the bn_add function test
__device__ void bn_add(BIGNUM *a, BIGNUM *b, BIGNUM *r);

// Test kernel for bn_add
__global__ void testKernel() {
    printf("++ testKernel for bn_add ++\n");

    // Set the maximum number of test cases
    const int num_tests = 4;

    // Test values for 'a' and 'b'
    BN_ULONG test_values_a[num_tests][MAX_BIGNUM_WORDS] = {
        {0x1},
        {0xFFFFFFFFFFFFFFFF},
        {0x0, 0x1}, // Representing 1 << 64 (2^64)
        {0x0, 0xFFFFFFFFFFFFFFFF}
    };

    BN_ULONG test_values_b[num_tests][MAX_BIGNUM_WORDS] = {
        {0x2},
        {0x1},
        {0x0, 0x2}, // Representing 2 << 64 (2^65)
        {0xFFFFFFFFFFFFFFFF, 0x1}
    };

    // Initialize 'a' and 'b' with test values for each test
    for (int test = 0; test < num_tests; ++test) {
        BIGNUM a, b, result;
        init_zero(&a, MAX_BIGNUM_WORDS);
        init_zero(&b, MAX_BIGNUM_WORDS);
        init_zero(&result, MAX_BIGNUM_WORDS);

        // Assign test values to 'a' and 'b', and initialize top accordingly
        for (int i = 0; i < MAX_BIGNUM_WORDS; ++i) {
            a.d[i] = test_values_a[test][i];
            b.d[i] = test_values_b[test][i];
        }
        a.top = (test < 2) ? 1 : 2; // For larger numbers, top would be 2
        b.top = (test < 2) ? 1 : 2;

        // Test addition
        bn_add(&result, &a, &b);

        // Print results
        printf("Test %d:\n", test + 1);
        bn_print("a     : ", &a);
        bn_print("b     : ", &b);
        bn_print("result: ", &result);
    }

    printf("-- Finished testKernel for bn_add --\n");
}

// Main function
int main() {
    printf("Starting bn_add test\n");
    // Launch the kernel to run the test
    testKernel<<<1, 1>>>();
    
    // Check for any errors after running the kernel
    cudaError_t err = cudaGetLastError();
    if (err != cudaSuccess) {
        printf("Error: %s\n", cudaGetErrorString(err));
        return -1;
    }
    
    // Wait for GPU to finish before accessing on host
    cudaDeviceSynchronize();
    return 0;
}
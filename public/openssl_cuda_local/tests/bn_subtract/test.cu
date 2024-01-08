#include <stdio.h>
#include <cuda_runtime.h>
#include "bignum.h"

// Define your BIGNUM structure based on your project definitions
#define MAX_BIGNUM_WORDS 20
#define BN_ULONG unsigned long long int
#define BN_ULONG_NUM_BITS (sizeof(BN_ULONG) * 8)

// Test kernel for bn_subtract
__global__ void testKernel() {
    printf("++ testKernel for bn_subtract ++\n");

    // Update the test values for subtraction based on previous OpenSSL test cases
    /*const int num_tests = 7;
    BN_ULONG test_values_a[num_tests][MAX_BIGNUM_WORDS] = {
        {0x1}, // 1-word
        {0x0, 0xDEF}, // 2-word
        {0x0, 0x0, 0x0, 0x10000}, // 4-word
        {0x0, 0x0, 0x0, 0x1234567890ABCDEFULL}, // 4-word
        {0x0, 0x0, 0x123456789ABCDEF0ULL, 0x123456789ABCDEF0ULL, 0x123456789ABCDEF0ULL, 0x12}, // 6-word
        {0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL}, // 2-word
        {0x1, 0x0, 0x0, 0x0, 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL, 0x1234567890ABCDEFULL} // 7-word
    };
    BN_ULONG test_values_b[num_tests][MAX_BIGNUM_WORDS] = {
        {0x0}, // 1-word
        {0x0, 0xABC}, // 2-word
        {0x0, 0x0, 0x0, 0xF}, // 4-word
        {0x0, 0x0, 0x0, 0x1000000000000000ULL}, // 4-word
        {0x0, 0x0, 0x1111111111111111ULL, 0x0, 0x0, 0x0}, // 6-word
        {0xFFFFFFFFFFFFFFFEULL, 0xFFFFFFFFFFFFFFFFULL}, // 2-word
        {0x00, 0x0, 0x0, 0x0, 0x0, 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL} // 7-word
    };*/
    // Test values 
    const int num_tests = 3;
    /*BN_ULONG test_values_a[num_tests][MAX_BIGNUM_WORDS] = {
        {0x1}, 
        {0x10, 0xDEF},
        {0xb0, c0x0, 0x10000, 0x1234567890ABCDEFULL}
    };

    BN_ULONG test_values_b[num_tests][MAX_BIGNUM_WORDS] = {
        {0x0}, 
        {0x8, 0xABC}, 
        {0xa0, 0xb0, 0xF, 0x1000000000000000ULL}
    };*/
    BN_ULONG test_values_a[num_tests][MAX_BIGNUM_WORDS] = {
        {0x1}, 
        {0x10, 0xDEF},
        {0xb0, 0xc0, 0x10000, 0x1234567890ABCDEFULL}
    };

    BN_ULONG test_values_b[num_tests][MAX_BIGNUM_WORDS] = {
        {0x0}, 
        {0x8, 0xABC}, 
        {0xa0, 0xb0, 0xF, 0x1000000000000000ULL}
    };

  
    // Run tests
    for (int test = 0; test < num_tests; ++test) {
        printf("\nTest %d:\n", test + 1);
        BIGNUM a, b, result;
        init_zero(&a, MAX_BIGNUM_WORDS);
        init_zero(&b, MAX_BIGNUM_WORDS);
        init_zero(&result, MAX_BIGNUM_WORDS);

        // Assign test values to 'a' and 'b', and initialize top accordingly
        for (int i = 0; i < MAX_BIGNUM_WORDS; ++i) {
            a.d[i] = test_values_a[test][i];
            b.d[i] = test_values_b[test][i];
        }
        a.top = find_top(&a, MAX_BIGNUM_WORDS);
        b.top = find_top(&b, MAX_BIGNUM_WORDS);

        // Perform the subtraction
        bn_subtract(&result, &a, &b);

        // Update result.top
        result.top = find_top(&result, MAX_BIGNUM_WORDS);

        // Print results
        bn_print("a: ", &a);
        bn_print("b: ", &b);
        bn_print("result: ", &result);
    }

    printf("-- Finished testKernel for bn_subtract --\n");
}

// Main function
int main() {
    printf("Starting\n");
    testKernel<<<1, 1>>>();
    cudaError_t err = cudaGetLastError();
    if (err != cudaSuccess) {
        printf("Error: %s\n", cudaGetErrorString(err));
        return -1;
    }
    cudaDeviceSynchronize();
    return 0;
}
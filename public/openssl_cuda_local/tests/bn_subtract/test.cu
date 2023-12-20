#include <stdio.h>
#include <cuda_runtime.h>
#define debug_print false
#include "bignum.h"

// Define your BIGNUM structure based on your project definitions
#define MAX_BIGNUM_WORDS 20
#define BN_ULONG unsigned long long int
#define BN_ULONG_NUM_BITS (sizeof(BN_ULONG) * 8)

// Test kernel for bn_subtract
__global__ void testKernel() {
    printf("++ testKernel for bn_subtract ++\n");

    const int num_tests = 4;
    // Initialize 'a' and 'b' with test values for each test
    BN_ULONG test_values_a[num_tests][MAX_BIGNUM_WORDS] = {
        {0x1}, // a small number to subtract from itself
        {0x0, 0x1}, // a larger number
        {0xFFFFFFFFFFFFFFFFULL, 0x1}, // a large number that will cause borrow
        {0xFFFFFFFFFFFFFFFFULL, 0x0} // a large number with a trailing zero
    };

    BN_ULONG test_values_b[num_tests][MAX_BIGNUM_WORDS] = {
        {0x1}, // same small number for subtraction
        {0x0, 0x0}, // smaller number
        {0x1}, // a smaller number that will cause borrow
        {0xFFFFFFFFFFFFFFFFULL} // the second large number with a leading zero
    };
  
    // Run tests
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
        a.top = find_top(&a, MAX_BIGNUM_WORDS);
        b.top = find_top(&b, MAX_BIGNUM_WORDS);

        // Perform the subtraction
        bn_subtract(&result, &a, &b);

        // Update result.top
        result.top = find_top(&result, MAX_BIGNUM_WORDS);

        // Print results
        printf("Test %d:\n", test + 1);
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

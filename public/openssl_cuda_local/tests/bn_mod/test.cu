#include <stdio.h>
#include <cuda_runtime.h>
#include "bignum.h"

#define TEST_BIGNUM_WORDS 1 // Adjust based on the highest number of words needed

// Test kernel for bn_divide
__global__ void testKernel() {
    printf("++ testKernel for bn_mod ++\n");
    // Test values for 'a'
    BN_ULONG test_values_a[] = {
        0x3ULL,           // Test Case 1
        0x64ULL,          // Test Case 2: 100 in decimal
        0x1ULL,           // Test Case 3
        0x4ULL,           // Test Case 4
        0x100003ULL,       // Test Case 5: Simplified large number for demonstration
        0x123456789ABCDEFULL // Test Case 6: Large prime number
    };

    // 'n' values (ensure these are real prime numbers for valid tests, except where prime is not required)
    BN_ULONG test_values_n[] = {
        0xBULL,           // Test Case 1: 11 in decimal
        0x65ULL,          // Test Case 2: 101 in decimal
        0xDULL,           // Test Case 3: 13 in decimal
        0x8ULL,           // Test Case 4: Non-prime, to show no inverse exists
        0x100019ULL,       // Test Case 5: Simplified large prime number for demonstration
        0xFEDCBA987654323ULL // Test Case 6: Large prime number
    };
    int sign_a[] = {0, 0, 0, 0, 0, 0}; // Signs for 'a', add -1 for negative numbers as needed
    int sign_n[] = {0, 0, 0, 0, 0, 0}; // Signs for 'b', add -1 for negative numbers as needed

    // int num_tests = sizeof(test_values_a) / sizeof(test_values_a[0]);
    const int num_tests = 6;

    // Initialize the word_num array
    int word_num[num_tests] = {1, 1, 1, 1, 1, 1};

    BIGNUM tmp;
    int mod;
    
    for (int test = 0; test < num_tests; ++test) {
        printf("\nTest %d:\n", test + 1);
        BIGNUM a, n, remainder;
        init_zero(&a, MAX_BIGNUM_WORDS);
        init_zero(&n, MAX_BIGNUM_WORDS);
        init_zero(&remainder, MAX_BIGNUM_WORDS);

        // Initialize 'a' and 'n' with the test values
        a.d[0] = test_values_a[test]; a.top = 1;
        n.d[0] = test_values_n[test]; n.top = 1;

        mod = bn_mod_for_div(&remainder, &a, &n);

        // Print results
        bn_print("remainder: ", &remainder);
        bn_print("a : ", &a);
        bn_print("n : ", &n);
        printf("mod: %d\n", mod);
    }
    printf("-- Finished testKernel for bn_divide --\n");
}

// Main function
int main() {
    printf("Starting bn_divide test\n");
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
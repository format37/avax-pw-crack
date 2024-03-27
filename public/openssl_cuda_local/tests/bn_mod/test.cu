#include <stdio.h>
#include <cuda_runtime.h>
#include "bignum.h"

#define TEST_BIGNUM_WORDS 2 // Adjust based on the highest number of words needed

// Test kernel for bn_divide
__global__ void testKernel() {
    printf("++ testKernel for bn_mod ++\n");
    /*// Test values for 'a'
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
    };*/
    // Test values for 'a' (dividends)
    BN_ULONG test_values_a[][TEST_BIGNUM_WORDS] = {
        {0x3ULL,0},                             // Test Case 1: Small positive number
        {0x64ULL},                            // Test Case 2: Medium positive number
        {0xFFFFFFFFFFFFFFFFULL},              // Test Case 3: Max unsigned 64-bit integer
        {0x0ULL},                             // Test Case 4: Zero
        {0x1ULL,0x0ULL},                     // Test Case 5: Large number spanning two words
        {0x123456789ABCDEFULL},               // Test Case 6: Large positive number
        {0x1ULL,0xFFFFFFFFFFFFFFFFULL},      // Test Case 7: Very large number just over one word size
        {0x1ULL}                              // Test Case 8: Division by zero, should return 0
    };

    // 'n' values (divisors)
    BN_ULONG test_values_n[][TEST_BIGNUM_WORDS] = {
        {0xBULL,0},                             // Test Case 1: Small prime number
        {0x65ULL},                            // Test Case 2: Composite number slightly larger than a
        {0x100000000ULL},                     // Test Case 3: Small power of 2 (larger than 64-bit values)
        {0x2ULL},                             // Test Case 4: Smallest even prime (edge case for even divisor)
        {0x1ULL,0x0ULL},                     // Test Case 5: Large prime spanning two words
        {0xFEDCBA987654323ULL},               // Test Case 6: Large prime number
        {0x1ULL,0x100000000ULL},             // Test Case 7: Larger power of 2 spanning two words
        {0x0ULL}                              // Test Case 8: Division by zero, should return 0
    };

    int sign_a[] = {0, 0, 0, 0, 0, 0, 0, 0}; // Signs for 'a', add -1 for negative numbers as needed
    int sign_n[] = {0, 0, 0, 0, 0, 0, 0, 0}; // Signs for 'b', add -1 for negative numbers as needed

    const int num_tests = 8;

    // Initialize the word_num array
    // int word_num[num_tests] = {1, 1, 1, 1, 1, 1};

    BIGNUM tmp;
    int mod;
    
    for (int test = 0; test < num_tests; ++test) {
        printf("\nTest %d:\n", test + 1);
        BIGNUM a, n, remainder;
        init_zero(&a, MAX_BIGNUM_WORDS);
        init_zero(&n, MAX_BIGNUM_WORDS);
        init_zero(&remainder, MAX_BIGNUM_WORDS);

        // Initialize 'a' and 'n' with the test values
        // a.d[0] = test_values_a[test]; a.top = 1;
        // n.d[0] = test_values_n[test]; n.top = 1;
        
        // Initialize 'a' and 'n' with the multiple word test values
        // for (int i = 0; i < word_num[test]; ++i) {
        for (int i = 0; i < TEST_BIGNUM_WORDS; ++i) {
            a.d[i] = test_values_a[test][i];
            n.d[i] = test_values_n[test][i];
        }
        a.top = TEST_BIGNUM_WORDS;
        n.top = TEST_BIGNUM_WORDS;

        mod = bn_mod(&remainder, &a, &n);

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

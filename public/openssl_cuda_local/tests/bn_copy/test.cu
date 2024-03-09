#include <stdio.h>
#include <cuda_runtime.h>
#include "bignum.h"

// Adjust the following definitions and include your project-specific BIGNUM operations
// #define MAX_BIGNUM_WORDS 20
// #define BN_ULONG unsigned long long int
// #define BN_ULONG_NUM_BITS (sizeof(BN_ULONG)*8)
#define TEST_BIGNUM_WORDS 2 // Adjust based on the highest number of words needed

__global__ void test_copy_kernel() {
    printf("++ test_kernel ++\n");

    // Test values for 'a'
    BN_ULONG test_values_b[][TEST_BIGNUM_WORDS] = {
        {0x0ULL},               // Test Case 1
        {0x3ULL},               // Test Case 2
        {0x32ULL},              // Test Case 3
        {0x123456789ABCDEFULL}, // Test Case 4
        {0x100003ULL, 0x123456789ABCDEFULL},            // Test Case 5
        {0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL}  // Test Case 6
    };

    int sign_b[] = {0, 0, 1, 0, 0, 1}; // Signs for 'a', add -1 for negative numbers as needed
    int word_count_b[] = {1, 1, 1, 1, 2, 2}; // Number of words for 'a'

    // Test different values of 'a' based on the test cases defined above
    int test_case_count = sizeof(test_values_b) / sizeof(test_values_b[0]);

    // Initialize BIGNUMs for testing
    BIGNUM a, b;

    for (int test = 0; test < test_case_count; ++test) {
        printf("\nTest %d:\n", test + 1);
        
        init_zero(&a, MAX_BIGNUM_WORDS);
        init_zero(&b, MAX_BIGNUM_WORDS);
        
        // Initialize 'a' with the test values
        for (int i = 0; i < word_count_b[test]; ++i) {
            b.d[i] = test_values_b[test][i];
        }
        b.top = find_top(&b, MAX_BIGNUM_WORDS);
        b.neg = sign_b[test];
        //printf("break\n");
        //break;
        // Print the values of 'a' and 'copy_of_a'
        bn_print("[0] a: ", &a);
        bn_print("[0] b: ", &b);
        
        
        // Perform bn_copy to copy 'a' to 'copy_of_a'
        bn_copy(&a, &b);

        // Print the values of 'a' and 'copy_of_a'
        bn_print("[1] a: ", &a);
        bn_print("[1] b: ", &b);

    }

    printf("-- Finished test_kernel --\n");
}

// Main function
int main() {
    printf("Starting bn_copy test\n");
    // Launch the kernel to run the test
    test_copy_kernel<<<1, 1>>>();

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
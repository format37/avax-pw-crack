#include <stdio.h>
#include <cuda_runtime.h>
#include "bignum.h"

#define TEST_BIGNUM_WORDS 2

__global__ void testKernel() {
    printf("++ testKernel for bn_gcdext ++\n");
    
    /*BN_ULONG test_values_a[][TEST_BIGNUM_WORDS] = {
        {0x123456789ABCDEFULL, 0x0}, // 1
        {0x1FFF3ULL, 0x0}, // 2
        {0xFEDCBA9876543210ULL, 0x0} // 3
    };

    BN_ULONG test_values_b[][TEST_BIGNUM_WORDS] = {
        {0xFEDCBA987654321ULL, 0x0}, // 1
        {0x2468ACEULL, 0x0}, // 2
        {0xFEDCBA9876543210ULL, 0x0} // 3
    };

    int sign_a[] = {0, 0, 0}; // Signs for 'a'
    int sign_b[] = {0, 0, 0}; // Signs for 'b'*/
    BN_ULONG test_values_a[][TEST_BIGNUM_WORDS] = {
        {0x123456789ABCDEFULL, 0x0}, // Original example 1
        {0x1FFF3ULL, 0x0}, // Original example 2
        {0xFEDCBA9876543210ULL, 0x0}, // Original example 3
        {0xFFFFFFFFFFFFFFFFULL, 0x1}, // Two-word case 1: Max value + 1 (overflow into the second word)
        {0x0, 0x1}, // Two-word case 2: A larger number that occupies the second word
        {0x123456789ABCDEFULL, 0xFEDCBA9876543210ULL} // Two-word case 3: Fully make use of two words
    };

    BN_ULONG test_values_b[][TEST_BIGNUM_WORDS] = {
        {0xFEDCBA987654321ULL, 0x0}, // Original example 1
        {0x2468ACEULL, 0x0}, // Original example 2
        {0xFEDCBA9876543210ULL, 0x0}, // Original example 3
        {0x0, 0x0}, // Edge case: One of the numbers is 0
        {0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL}, // Edge case: Both numbers equal, also a two-word case
        {0xFFFFFFFFFFFFFFFFULL, 0x1} // Mixed case: Significantly different values across words
    };

    // int sign_a[] = {0, 0, 0, 0, 0}; // Signs for 'a', add -1 for negative numbers as needed
    // int sign_b[] = {0, 0, 0, 0, 0}; // Signs for 'b', add -1 for negative numbers as needed
    int sign_a[] = {0, 0, 0, 0, 0, 0}; // Signs for 'a', add -1 for negative numbers as needed    
    int sign_b[] = {0, 0, 0, 0, 0, 0}; // Signs for 'b', add -1 for negative numbers as needed
    
    int num_tests = sizeof(test_values_a) / (sizeof(BN_ULONG) * TEST_BIGNUM_WORDS);

    for (int test = 0; test < num_tests; ++test) {
        BIGNUM a, b, g;//, s, t;
        init_zero(&a, TEST_BIGNUM_WORDS);
        init_zero(&b, TEST_BIGNUM_WORDS);
        init_zero(&g, TEST_BIGNUM_WORDS);
        /*init_zero(&s, TEST_BIGNUM_WORDS);
        init_zero(&t, TEST_BIGNUM_WORDS);*/

        // Initialize 'a' and 'b' with the test values
        for (int j = 0; j < TEST_BIGNUM_WORDS; ++j) {
            a.d[j] = test_values_a[test][j];
            b.d[j] = test_values_b[test][j];
        }
        a.top = find_top(&a, TEST_BIGNUM_WORDS);
        b.top = find_top(&b, TEST_BIGNUM_WORDS);

        a.neg = sign_a[test];
        b.neg = sign_b[test];
        
        printf("Test %d:\n", test + 1);
        bn_print("a: ", &a);
        bn_print("b: ", &b);

        // Test gcdext
        //bn_gcdext(&g, &s, &t, &a, &b);
        //bn_gcd(&g, &a, &b);
        bn_gcd(&g, &a, &b);

        // Print result
        bn_print("gcd: ", &g);
        /*bn_print("s: ", &s);
        bn_print("t: ", &t);*/
    }
    printf("-- Finished testKernel for bn_gcdext --\n");
}

// Main function
int main() {
    printf("Starting bn_gcdext test\n");
    testKernel<<<1, 1>>>();
    cudaError_t err = cudaGetLastError();
    if (err != cudaSuccess) {
        printf("Error: %s\n", cudaGetErrorString(err));
        return -1;
    }
    cudaDeviceSynchronize();
    return 0;
}
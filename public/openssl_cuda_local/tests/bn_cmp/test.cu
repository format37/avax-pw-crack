#include <stdio.h>
#include <cuda_runtime.h>
#include "bignum.h"

#define TEST_BIGNUM_WORDS 2


__global__ void testKernel() {
    printf("++ testKernel for bn_cmp ++\n");

    BN_ULONG test_values_a[][TEST_BIGNUM_WORDS] = {
        {0x1}, // 0
        {0x1}, // 1
        {0x0, 0x1}, // 2
        {0xFFFFFFFFFFFFFFFFULL}, // 3
        {0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL}, // 4
        {0xFFFFFFFFFFFFFFFFULL, 0x0}, // 5
        {0xFFFFFFFFFFFFFFFFULL}, // 6
        {0x1}, // 7
        {0xFFFFFFFFFFFFFFFFULL}, // 8
        {0x1}, // 9
        {0x0, 0x1}, // 10
        {0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL} // 11
    };
    BN_ULONG test_values_b[][TEST_BIGNUM_WORDS] = {
        {0x1}, // 0
        {0x0, 0x1}, // 1
        {0x1}, // 2
        {0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL}, // 3
        {0xFFFFFFFFFFFFFFFFULL, 0x0}, // 4
        {0xFFFFFFFFFFFFFFFFULL}, // 5
        {0xFFFFFFFFFFFFFFFFULL}, // 6
        {0xFFFFFFFFFFFFFFFFULL}, // 7
        {0x1}, // 8
        {0x1}, // 9 
        {0x0, 0x1}, // 10
        {0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL} // 11
    };
    
    int sign_a[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}; // Signs for 'a'
    int sign_b[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0}; // Signs for 'b'

    // Run through test value comparisons
    for (int i = 0; i < sizeof(test_values_a) / sizeof(test_values_a[0]); ++i) {

        BIGNUM a, b;
        init_zero(&a, TEST_BIGNUM_WORDS);
        init_zero(&b, TEST_BIGNUM_WORDS);

        // Initialize BIGNUM a
        for (int j = 0; j < TEST_BIGNUM_WORDS; ++j) {
            a.d[j] = test_values_a[i][j];
        }
        a.top = find_top(&a, TEST_BIGNUM_WORDS);
        a.neg = sign_a[i];
        
        // Initialize BIGNUM b
        for (int j = 0; j < TEST_BIGNUM_WORDS; ++j) {
            b.d[j] = test_values_b[i][j];
        }
        b.top = find_top(&b, TEST_BIGNUM_WORDS);
        b.neg = sign_b[i];

        //printf("Comparing a and b:\n");
        printf("\n%d. Comparing a and b:\n", i);
        bn_print("a: ", &a);
        bn_print("b: ", &b);

        // Now compare a and b using bn_cmp
        int cmp_result = bn_cmp(&a, &b);

        // Print results
        printf("Result of comparison: %d\n", cmp_result);
    }
    printf("-- Finished testKernel for bn_cmp --\n");
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

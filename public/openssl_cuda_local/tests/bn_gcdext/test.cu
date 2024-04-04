#include <stdio.h>
#include <cuda_runtime.h>
#include "bignum.h"

#define TEST_BIGNUM_WORDS 4

__device__ void reverse_order(BN_ULONG test_values_a[][TEST_BIGNUM_WORDS], BN_ULONG test_values_b[][TEST_BIGNUM_WORDS], size_t num_rows) {
    for (size_t i = 0; i < num_rows; i++) {
        for (size_t j = 0; j < TEST_BIGNUM_WORDS / 2; j++) {
            BN_ULONG temp_a = test_values_a[i][j];
            test_values_a[i][j] = test_values_a[i][TEST_BIGNUM_WORDS - 1 - j];
            test_values_a[i][TEST_BIGNUM_WORDS - 1 - j] = temp_a;

            BN_ULONG temp_b = test_values_b[i][j];
            test_values_b[i][j] = test_values_b[i][TEST_BIGNUM_WORDS - 1 - j];
            test_values_b[i][TEST_BIGNUM_WORDS - 1 - j] = temp_b;
        }
    }
}

__global__ void testKernel() {
    printf("++ testKernel for bn_gcdext ++\n");
    BN_ULONG test_values_a[][TEST_BIGNUM_WORDS] = {
        {0,0,0,0x3},                    // 1
        /*{0,0,0x123456789ABCDEFULL,0},   // 2
        {0,0,0x1FFF3ULL,0},             // 3
        {0,0,0xFEDCBA9876543210ULL,0},  // 4
        {0,0,0xFFFFFFFFFFFFFFFFULL,0x1},// 5
        {0,0,0,0x1},                    // 6
        {0,0,0x123456789ABCDEFULL,0xFEDCBA9876543210ULL} // 7*/
    };

    BN_ULONG test_values_b[][TEST_BIGNUM_WORDS] = {
        {0,0,0,0xb},                    // 1
        /*{0,0,0xFEDCBA987654321ULL,0},   // 2
        {0,0,0x2468ACEULL,0},           // 3
        {0,0,0xFEDCBA9876543210ULL,0},  // 4
        {0,0,0,0},                      // 5
        {0,0,0xFFFFFFFFFFFFFFFFULL,0xFFFFFFFFFFFFFFFFULL}, // 6
        {0,0,0xFFFFFFFFFFFFFFFFULL,0x1}                    // 7*/
    };
    reverse_order(test_values_a, test_values_b, sizeof(test_values_a) / (sizeof(BN_ULONG) * TEST_BIGNUM_WORDS));

    //int sign_a[] = {0, 0, 0, 0, 0}; // Signs for 'a', add -1 for negative numbers as needed
    //int sign_b[] = {0, 0, 0, 0, 0}; // Signs for 'b', add -1 for negative numbers as needed
    
    int num_tests = sizeof(test_values_a) / (sizeof(BN_ULONG) * TEST_BIGNUM_WORDS);

    for (int test = 0; test < num_tests; ++test) {
        BIGNUM a, b, g, s, t;
        init_zero(&a, TEST_BIGNUM_WORDS);
        init_zero(&b, TEST_BIGNUM_WORDS);
        init_zero(&g, TEST_BIGNUM_WORDS);
        init_zero(&s, TEST_BIGNUM_WORDS);
        init_zero(&t, TEST_BIGNUM_WORDS);

        // Initialize 'a' and 'b' with the test values
        for (int j = 0; j < TEST_BIGNUM_WORDS; ++j) {
            a.d[j] = test_values_a[test][j];
            b.d[j] = test_values_b[test][j];
        }
        a.top = find_top(&a, TEST_BIGNUM_WORDS);
        b.top = find_top(&b, TEST_BIGNUM_WORDS);

        //a.neg = sign_a[test];
        //b.neg = sign_b[test];
        
        printf("\n]================>> Test %d:\n", test + 1);
        bn_print("a: ", &a);
        bn_print("b: ", &b);

        // Test gcdext
        bn_gcdext(&g, &s, &t, &a, &b);

        // Print result
        bn_print("gcd: ", &g);
        bn_print("s: ", &s);
        bn_print("t: ", &t);
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
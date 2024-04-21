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
    printf("++ testKernel for bn_mod ++\n");
    BN_ULONG test_values_a[][MAX_BIGNUM_WORDS] = {
        {0xffffffffffffffff, 0xffffffffffffffe, 0xbaaedce6af48a03b, 0xbfd25e8cd0364141},

    };

    BN_ULONG test_values_n[][MAX_BIGNUM_WORDS] = {
        {0x1b2db4c027cdbaba, 0x70116675aa53aa8a, 0xad1c289591e564d3, 0xcaa5c571ffccab5a},
    };

    int mod;

    // 0 for positive, 1 for negative
    //int sign_a[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0};
    //int sign_n[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0};
    int sign_a[] = {0};
    int sign_n[] = {0};
    
    reverse_order(test_values_a, test_values_n, sizeof(test_values_a) / (sizeof(BN_ULONG) * TEST_BIGNUM_WORDS));
    
    int num_tests = sizeof(test_values_a) / (sizeof(BN_ULONG) * TEST_BIGNUM_WORDS);
    for (int test = 0; test < num_tests; ++test) {
        BIGNUM value_a, value_n, remainder;
        init_zero(&value_a, TEST_BIGNUM_WORDS);
        init_zero(&value_n, TEST_BIGNUM_WORDS);
        init_zero(&remainder, TEST_BIGNUM_WORDS);

        // Initialize 'value_a' and 'value_n' with the test values
        for (int j = 0; j < TEST_BIGNUM_WORDS; ++j) {
            value_a.d[j] = test_values_a[test][j];
            value_n.d[j] = test_values_n[test][j];
        }
        value_a.top = find_top(&value_a, TEST_BIGNUM_WORDS);
        value_n.top = find_top(&value_n, TEST_BIGNUM_WORDS);

        //value_a.neg = sign_a[test];
        //value_n.neg = sign_b[test];

        printf("\n]================>> Test %d:\n", test);
        bn_print("a: ", &value_a);
        bn_print("n: ", &value_n);

        mod = bn_mod(&remainder, &value_a, &value_n);

        // Print results
        bn_print("remainder: ", &remainder);
        bn_print("a : ", &value_a);
        bn_print("n : ", &value_n);
        printf("mod: %d\n", mod);
    }
}

// Main function
int main() {
    testKernel<<<1, 1>>>();
    cudaError_t err = cudaGetLastError();
    if (err != cudaSuccess) {
        printf("Error: %s\n", cudaGetErrorString(err));
        return -1;
    }
    cudaDeviceSynchronize();
    return 0;
}
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
    printf("++ testKernel for bn_mod_inverse ++\n");
    BN_ULONG test_values_a[][MAX_BIGNUM_WORDS] = {
        {0,0,0,0x3}, // 0
    };
    BN_ULONG test_values_n[][MAX_BIGNUM_WORDS] = {
        {0,0,0,0xB}, // 0
    };
    reverse_order(test_values_a, test_values_n, sizeof(test_values_a) / (sizeof(BN_ULONG) * TEST_BIGNUM_WORDS));

    //int sign_a[] = {0, 0, 0, 0, 0}; // Signs for 'a', add -1 for negative numbers as needed
    //int sign_b[] = {0, 0, 0, 0, 0}; // Signs for 'b', add -1 for negative numbers as needed
    
    int num_tests = sizeof(test_values_a) / (sizeof(BN_ULONG) * TEST_BIGNUM_WORDS);

    for (int test = 0; test < num_tests; ++test) {
        BIGNUM value_a, value_n, result;
        init_zero(&value_a, TEST_BIGNUM_WORDS);
        init_zero(&value_n, TEST_BIGNUM_WORDS);
        init_zero(&result, TEST_BIGNUM_WORDS);

        // Initialize 'value_a' and 'value_n' with the test values
        for (int j = 0; j < TEST_BIGNUM_WORDS; ++j) {
            value_a.d[j] = test_values_a[test][j];
            value_n.d[j] = test_values_n[test][j];
        }
        value_a.top = find_top(&value_a, TEST_BIGNUM_WORDS);
        value_n.top = find_top(&value_n, TEST_BIGNUM_WORDS);

        //value_a.neg = sign_a[test];
        //value_n.neg = sign_b[test];

        printf("\n]================>> Test %d:\n", test + 1);
        bn_print("a: ", &value_a);
        bn_print("n: ", &value_n);

        // Test the bn_mod_inverse function
        bn_mod_inverse(&result, &value_a, &value_n);
        // Print the result
        bn_print("Modular inverse: ", &result);
        printf("\n");
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
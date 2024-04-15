//bn_div_test.cu
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
    BN_ULONG test_values_dividend[][MAX_BIGNUM_WORDS] = {
        {0,0,0,0xb}, // 0
        {0,0,0,0x3}, // 1
    };

    BN_ULONG test_values_divisor[][MAX_BIGNUM_WORDS] = {
        {0,0,0,0x3}, // 0
        {0,0,0,0xb}, // 1
    };
    reverse_order(test_values_dividend, test_values_divisor, sizeof(test_values_dividend) / (sizeof(BN_ULONG) * TEST_BIGNUM_WORDS));

    //int sign_a[] = {0, 0, 0, 0, 0}; // Signs for 'a', add -1 for negative numbers as needed
    //int sign_b[] = {0, 0, 0, 0, 0}; // Signs for 'b', add -1 for negative numbers as needed
    
    int num_tests = sizeof(test_values_dividend) / (sizeof(BN_ULONG) * TEST_BIGNUM_WORDS);

    int success = 0;

    for (int test = 0; test < num_tests; ++test) {
        BIGNUM dividend, divisor, quotient, remainder;
        init_zero(&dividend, TEST_BIGNUM_WORDS);
        init_zero(&divisor, TEST_BIGNUM_WORDS);
        init_zero(&quotient, TEST_BIGNUM_WORDS);
        init_zero(&remainder, TEST_BIGNUM_WORDS);

        // Initialize 'dividend' and 'divisor' with the test values
        for (int j = 0; j < TEST_BIGNUM_WORDS; ++j) {
            dividend.d[j] = test_values_dividend[test][j];
            divisor.d[j] = test_values_divisor[test][j];
        }
        dividend.top = find_top(&dividend, TEST_BIGNUM_WORDS);
        divisor.top = find_top(&divisor, TEST_BIGNUM_WORDS);

        //dividend.neg = sign_a[test];
        //divisor.neg = sign_b[test];

        printf("\n]==>> Test %d:\n", test);
        bn_print("dividend: ", &dividend);
        bn_print("n: ", &divisor);

        // Test division
        success = bn_div(&quotient, &remainder, &dividend, &divisor);
        // Print results
        if (success) {
            printf("Success\n");
        } else {
            printf("Failure\n");
        }
        bn_print("# quotient : ", &quotient);
        bn_print("# remainder: ", &remainder);
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
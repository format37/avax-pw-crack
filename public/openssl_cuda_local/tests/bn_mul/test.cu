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

    BN_ULONG test_values_dividend[][TEST_BIGNUM_WORDS] = {
        {0xd2a68e877f99fed4, 0x4620881d385be245, 0xfade7e1c8be17cc7, 0x871c611855bf0ca1},
    };

    BN_ULONG test_values_divisor[][TEST_BIGNUM_WORDS] = {
        {0xac946f7cd9ccebb8, 0xd59803e73c7d12aa, 0x395b2eb7e59a8ba1, 0x19742df442fc6604},
    };

    reverse_order(test_values_dividend, test_values_divisor, sizeof(test_values_dividend) / (sizeof(BN_ULONG) * TEST_BIGNUM_WORDS));

    int sign_a[] = {0,0}; // Signs for 'a', add -1 for negative numbers as needed
    int sign_b[] = {0,0}; // Signs for 'b', add -1 for negative numbers as needed
    
    int num_tests = sizeof(test_values_dividend) / (sizeof(BN_ULONG) * TEST_BIGNUM_WORDS);

    int success = 0;

    for (int test = 0; test < num_tests; ++test) {
        BIGNUM dividend, divisor, quotient, remainder;
        init_zero(&dividend, TEST_BIGNUM_WORDS);
        init_zero(&divisor, TEST_BIGNUM_WORDS);

        // Initialize 'dividend' and 'divisor' with the test values
        for (int j = 0; j < TEST_BIGNUM_WORDS; ++j) {
            dividend.d[j] = test_values_dividend[test][j];
            divisor.d[j] = test_values_divisor[test][j];
        }
        dividend.top = find_top(&dividend, TEST_BIGNUM_WORDS);
        divisor.top = find_top(&divisor, TEST_BIGNUM_WORDS);

        dividend.neg = sign_a[test];
        divisor.neg = sign_b[test];

        printf("\n]==>> Test %d:\n", test);
        bn_print("a: ", &dividend);
        bn_print("b: ", &divisor);

        // Test division
        BIGNUM temp, product;
        init_zero(&product, TEST_BIGNUM_WORDS);
        bn_mul(&dividend, &divisor, &product);
        // print product
        bn_print("product: ", &product);
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
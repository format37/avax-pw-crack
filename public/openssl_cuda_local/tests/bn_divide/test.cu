//bn_div_test.cu
#include <stdio.h>
#include <cuda_runtime.h>
#include "bignum.h"

#define TEST_BIGNUM_WORDS 10

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
        //{0,0xa9d76a4234a8ded, 0x7af964ec3f6f871b, 0xe09d7f67cc580732, 0x3b11b98c6222abbb, 0x0bdfd291448c33e6, 0xa46834fe88684cf0, 0x5106877163ee71eb, 0x5186b6de04720283},
        {
            0,
            0,
            0,
            0,
            0,
            0x1,
            0x2e09165b257a4c3e,
            0x52c9f4faa6322c65,
            0x898d5d622cb3eeff,
            0x55da7f062f1b85c0
        }
    };

    BN_ULONG test_values_divisor[][TEST_BIGNUM_WORDS] = {
        //{0, 0, 0, 0, 0, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xfffffffefffffc2f},
        {
            0,
            0,
            0,
            0,
            0,
            0,
            0xffffffffffffffff,
            0xfffffffffffffffe,
            0xbaaedce6af48a03b,
            0xbfd25e8cd0364141
        }
    };

    reverse_order(test_values_dividend, test_values_divisor, sizeof(test_values_dividend) / (sizeof(BN_ULONG) * TEST_BIGNUM_WORDS));

    int sign_a[] = {0}; // Signs for 'a', add -1 for negative numbers as needed
    int sign_b[] = {0}; // Signs for 'b', add -1 for negative numbers as needed
    
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

        dividend.neg = sign_a[test];
        divisor.neg = sign_b[test];

        printf("\n]==>> Test %d:\n", test);
        bn_print("dividend: ", &dividend);
        bn_print("n: ", &divisor);

        // Test division
        success = bn_div(&quotient, &remainder, &dividend, &divisor);
        // Print results
        // if (success) {
        //     printf("Success\n");
        // } else {
        //     printf("Failure\n");
        // }
        bn_print("# quotient : ", &quotient);
        bn_print("# remainder: ", &remainder);
        printf("\n");
        // dividend
        // -------- = quotient, remainder
        // divisor
        // Multiplication back: quotient * divisor + remainder = dividend
        BIGNUM temp, product;
        init_zero(&temp, TEST_BIGNUM_WORDS);
        init_zero(&product, TEST_BIGNUM_WORDS);
        bn_mul(&quotient, &divisor, &product);
        // print product
        bn_print("product: ", &product);
        // add remainder
        bn_add(&temp, &product, &remainder);
        // print temp
        bn_print("temp: ", &temp);
        // print dividend
        bn_print("initial dividend: ", &dividend);
    }
      
}

// Main function
int main() {
    cudaDeviceProp device_prop;
    cudaGetDeviceProperties(&device_prop, 0);
    int clock_rate = device_prop.clockRate;
    printf("Device clock rate: %d\n", clock_rate);

    testKernel<<<1, 1>>>();
    cudaError_t err = cudaGetLastError();
    if (err != cudaSuccess) {
        printf("Error: %s\n", cudaGetErrorString(err));
        return -1;
    }
    cudaDeviceSynchronize();
    return 0;
}
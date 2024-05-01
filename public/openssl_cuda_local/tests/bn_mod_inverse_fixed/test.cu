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
        /*{0,0,0,0x3},     // 0: a = 3, n = 11
        {0,0,0,0x2A},    // 1: a = 42, n = 2017
        {0,0,0,0x4D2},   // 2: a = 1234, n = 5678
        {0,0,0,0x0},     // 3: a = 0, n = 11
        {0,0,0,0x1},     // 4: a = 1, n = 11
        {0,0,0,0xA},     // 5: a = 10, n = 11
        {0,0,0,0xB},     // 6: a = 11, n = 11
        {0,0,0,0x3},     // 7: a = 3, n = 1
        {0,0,0,0x3},     // 8: a = 3, n = 2
        {0,0,0,0x3},     // 9: a = 3, n = 11 (for negative 'a' test case)
        {0,0,0,0x3},     // 10: a = 3, n = 11 (for negative 'n' test case)
        {0,0,0,0x3},     // 11: a = 3, n = 11 (for negative 'a' and 'n' test case)
        {0,0,0,0x2A},    // 12: a = 42, n = 2017 (for negative 'a' test case)
        {0,0,0,0x4D2},   // 13: a = 1234, n = 5678 (for negative 'n' test case)
        {0,0x11F71B54,0x92EA6E0,0},    // 14: a = 1234567890, n = 9876543210
        {0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF},    // 15: a = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF, n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
        {0,0,0,0x4},     // 16: a = 4, n = 12
        {0,0,0,0x6},     // 17: a = 6, n = 15
        {0,0,0,0x12},    // 18: a = 18, n = 24*/
        // {0xffffffffffffffff, 0xffffffffffffffe, 0xbaaedce6af48a03b, 0xbfd25e8cd0364141},
        // {0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xfffffffefffffc2f},
        {0x35c2d1fd4c7b8673, 0x478b08328cd9d5dd, 0xefec64ca64cda1c2, 0x46c86352a19fca54},
        //{0x46c86352a19fca54, 0xefec64ca64cda1c2, 0x478b08328cd9d5dd, 0x35c2d1fd4c7b8673},
    };

    BN_ULONG test_values_n[][MAX_BIGNUM_WORDS] = {
        /*{0,0,0,0xB},     // 0: a = 3, n = 11
        {0,0,0,0x7E1},   // 1: a = 42, n = 2017
        {0,0,0,0x162E},  // 2: a = 1234, n = 5678
        {0,0,0,0xB},     // 3: a = 0, n = 11
        {0,0,0,0xB},     // 4: a = 1, n = 11
        {0,0,0,0xB},     // 5: a = 10, n = 11
        {0,0,0,0xB},     // 6: a = 11, n = 11
        {0,0,0,0x1},     // 7: a = 3, n = 1
        {0,0,0,0x2},     // 8: a = 3, n = 2
        {0,0,0,0xB},     // 9: a = 3, n = 11 (for negative 'a' test case)
        {0,0,0,0xB},     // 10: a = 3, n = 11 (for negative 'n' test case)
        {0,0,0,0xB},     // 11: a = 3, n = 11 (for negative 'a' and 'n' test case)
        {0,0,0,0x7E1},   // 12: a = 42, n = 2017 (for negative 'a' test case)
        {0,0,0,0x162E},  // 13: a = 1234, n = 5678 (for negative 'n' test case)
        {0,0x2456AF20,0x962E90,0},    // 14: a = 1234567890, n = 9876543210
        {0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF},    // 15: a = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF, n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
        {0,0,0,0xC},     // 16: a = 4, n = 12
        {0,0,0,0xF},     // 17: a = 6, n = 15
        {0,0,0,0x18},    // 18: a = 18, n = 24*/
        // {0x1b2db4c027cdbaba, 0x70116675aa53aa8a, 0xad1c289591e564d3, 0xcaa5c571ffccab5a},
        // {0x4c4619154810c1c0, 0xdaa4ddd8c73971d1, 0x59db91705f2113ce, 0x51b9885e4578874d},
        {0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xfffffffefffffc2f},
        //{0xfffffffefffffc2f, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff},
    };

    // 0 for positive, 1 for negative
    //int sign_a[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0};
    //int sign_n[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0};
    int sign_a[] = {0};
    int sign_n[] = {0};
    
    reverse_order(test_values_a, test_values_n, sizeof(test_values_a) / (sizeof(BN_ULONG) * TEST_BIGNUM_WORDS));
    
    int num_tests = sizeof(test_values_a) / (sizeof(BN_ULONG) * TEST_BIGNUM_WORDS);
    int limit = 20;
    bool mod_inverse_exists;
    for (int test = 0; test < num_tests; ++test) {
        BIGNUM value_a, value_n, result;
        init_zero(&value_a, MAX_BIGNUM_SIZE);
        init_zero(&value_n, MAX_BIGNUM_SIZE);
        init_zero(&result, MAX_BIGNUM_SIZE);

        // Initialize 'value_a' and 'value_n' with the test values
        for (int j = 0; j < TEST_BIGNUM_WORDS; ++j) {
            value_a.d[j] = test_values_a[test][j];
            value_n.d[j] = test_values_n[test][j];
        }
        value_a.top = find_top(&value_a, MAX_BIGNUM_SIZE);
        value_n.top = find_top(&value_n, MAX_BIGNUM_SIZE);

        //value_a.neg = sign_a[test];
        //value_n.neg = sign_b[test];

        printf("\n]================>> Test %d:\n", test);
        bn_print("a: ", &value_a);
        bn_print("n: ", &value_n);

        // Test the bn_mod_inverse function
        mod_inverse_exists = bn_mod_inverse(&result, &value_a, &value_n);
        // Print the result
        printf("[%d] ", test);
        if (mod_inverse_exists) bn_print("Modular inverse: ", &result);
        else printf("No modular inverse exists for the given 'a' and 'n'.\n");
        printf("\n");
        limit -= 1;
        if (limit == 0) {
            break;
        }
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
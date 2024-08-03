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

    // reverse_order(test_values_dividend, test_values_divisor, sizeof(test_values_dividend) / (sizeof(BN_ULONG) * TEST_BIGNUM_WORDS));
    // Convert scalar BIGNUM to an array of integers that's easy to iterate bit-wise
    BIGNUM scalar;
    init_zero(&scalar);
    // init scalar.d as bbc611b700cbdb5c8361c267c2587992cac0bb2d97f0a86f6334ec00a7210d9c
    scalar.d[0] = 0x6334ec00a7210d9c;
    scalar.d[1] = 0xcac0bb2d97f0a86f;
    scalar.d[2] = 0x8361c267c2587992;
    scalar.d[3] = 0xbbc611b700cbdb5c;
    scalar.top = 4;
    unsigned int bits[256];                          // Assuming a 256-bit scalar
    bignum_to_bit_array(&scalar, bits);
    for (int i = 0; i < 256; i++) {
        printf("%d: %u\n", i, bits[i]);
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
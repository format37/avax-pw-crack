#include <stdio.h>
#include <cuda_runtime.h>
#include "bignum.h"

#define TEST_BIGNUM_WORDS 9

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

__device__ void reverse_order_single(BIGNUM *test_values_a) {
    for (size_t j = 0; j < TEST_BIGNUM_WORDS / 2; j++) {
        BN_ULONG temp_a = test_values_a->d[j];
        test_values_a->d[j] = test_values_a->d[TEST_BIGNUM_WORDS - 1 - j];
        test_values_a->d[TEST_BIGNUM_WORDS - 1 - j] = temp_a;
    }
}

__global__ void testKernel() {
    printf("++ CUDA compress public key ++\n");

    EC_POINT G;
    init_point_at_infinity(&G);
    // 66c1981565aedcc419cc56e72954e62fa0c3f43955b99a6a835afa2f29a7a7b6
    // 49f4aa5706a41b7f0f26cb03375787701556e5f3b9d7f6dd53befd80dcfecd8f
    BN_ULONG test_values_x[][MAX_BIGNUM_WORDS] = {
        {0,0,0,0,0,0x66c1981565aedcc4, 0x19cc56e72954e62f, 0xa0c3f43955b99a6a, 0x835afa2f29a7a7b6},
    };

    BN_ULONG test_values_y[][MAX_BIGNUM_WORDS] = {
        {0,0,0,0,0,0x49f4aa5706a41b7f, 0x0f26cb0337578770, 0x1556e5f3b9d7f6dd, 0x53befd80dcfecd8f},
    };

    unsigned int test = 0;

    // Initialize 'value_a' and 'value_n' with the test values
    for (int j = 0; j < TEST_BIGNUM_WORDS; ++j) {
        G.x.d[j] = test_values_x[test][j];
        G.y.d[j] = test_values_y[test][j];
    }
    G.x.top = find_top(&G.x, MAX_BIGNUM_SIZE);
    G.y.top = find_top(&G.y, MAX_BIGNUM_SIZE);

    reverse_order_single(&G.x);
    reverse_order_single(&G.y);
    
    bn_print(">> G.x: ", &G.x);
    bn_print(">> G.y: ", &G.y);

    char* compressed = compress_public_key(G);
    printf(">> Compressed public key: %s\n", compressed);

    printf("\n");
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
#include <stdio.h>
#include <cuda_runtime.h>
#include "bignum.h"
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <string.h>

#define BN_ULONG_HOST unsigned long long
#ifdef BN_128
    #define MAX_BIGNUM_SIZE_HOST MAX_BIGNUM_SIZE * 2
#else
    #define MAX_BIGNUM_SIZE_HOST MAX_BIGNUM_SIZE
#endif

__global__ void kernel_test_find_top(BN_ULONG_HOST *A, int *Result) {
    BIGNUM a;
    init_zero(&a);

    #ifdef BN_128
        for (int i = 0; i < MAX_BIGNUM_SIZE; i++) {
            a.d[i] = ((__int128)A[i*2+1] << 64) | A[i*2];
        }
    #else
        for (int i = 0; i < MAX_BIGNUM_SIZE; i++) {
            a.d[i] = A[i];
        }
    #endif

    *Result = find_top(&a);
}

int main() {
    #ifdef BN_128
        printf("\nBN_128\n");
    #else
        printf("\nBN_64\n");
    #endif

    BN_ULONG_HOST test_values[][MAX_BIGNUM_SIZE_HOST] = {
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0},  // All zeros
        {1, 0, 0, 0, 0, 0, 0, 0, 0, 0},  // Only lowest word non-zero
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 1},  // Only highest word non-zero
        {1, 2, 3, 4, 5, 0, 0, 0, 0, 0},  // First 5 words non-zero
        {0, 0, 0, 0, 0, 5, 4, 3, 2, 1},  // Last 5 words non-zero
        {1, 1, 1, 1, 1, 1, 1, 1, 1, 1},  // All words non-zero
        {0xFFFFFFFFFFFFFFFF, 0, 0, 0, 0, 0, 0, 0, 0, 0},  // Max value in lowest word
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFFFFFFFFFFFFFFFF},  // Max value in highest word
    };

    int num_tests = sizeof(test_values) / sizeof(test_values[0]);

    printf("\n### CUDA find_top test:\n");

    BN_ULONG_HOST *d_A;
    int *d_Result;
    cudaMalloc((void**)&d_A, MAX_BIGNUM_SIZE_HOST * sizeof(BN_ULONG_HOST));
    cudaMalloc((void**)&d_Result, sizeof(int));

    for (int i = 0; i < num_tests; i++) {
        printf("\nTest %d:\n", i);

        // Copy test data to device
        cudaMemcpy(d_A, test_values[i], MAX_BIGNUM_SIZE_HOST * sizeof(BN_ULONG_HOST), cudaMemcpyHostToDevice);

        // Run kernel
        kernel_test_find_top<<<1, 1>>>(d_A, d_Result);

        // Check for errors
        cudaError_t err = cudaGetLastError();
        if (err != cudaSuccess) {
            printf("Error: %s\n", cudaGetErrorString(err));
        }

        cudaDeviceSynchronize();

        // Copy result back to host
        int cuda_result;
        cudaMemcpy(&cuda_result, d_Result, sizeof(int), cudaMemcpyDeviceToHost);

        // Calculate expected result
        int expected_result = 1;
        #ifdef BN_128
            for (int idx = MAX_BIGNUM_SIZE - 1; idx >= 0; idx--) {
                BN_ULONG_HOST high = test_values[i][idx * 2 + 1];
                BN_ULONG_HOST low = test_values[i][idx * 2];
                __int128 bn_di = ((__int128)high << 64) | low;
                if (bn_di != 0) {
                    expected_result = idx + 1;
                    break;
                }
            }
        #else
            for (int j = MAX_BIGNUM_SIZE_HOST - 1; j >= 0; j--) {
                if (test_values[i][j] != 0) {
                    expected_result = j + 1;
                    break;
                }
            }
        #endif

        // Compare results
        if (cuda_result == expected_result) {
            printf("Test PASSED: find_top returned %d\n", cuda_result);
        } else {
            printf("### Test FAILED: find_top returned %d, expected %d ###\n", cuda_result, expected_result);
            printf("Test value: ");
            for (int j = MAX_BIGNUM_SIZE_HOST - 1; j >= 0; j--) {
                printf("%016llx ", test_values[i][j]);
            }
            printf("\n");
        }
    }

    cudaFree(d_A);
    cudaFree(d_Result);

    return 0;
}
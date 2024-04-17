#include <stdio.h>
#include <cuda_runtime.h>
#include "bignum.h"

__global__ void test(BN_ULONG *A, BN_ULONG *N) {
    BIGNUM value_a, value_n, result;
    init_zero(&value_a, MAX_BIGNUM_WORDS);
    init_zero(&value_n, MAX_BIGNUM_WORDS);
    init_zero(&result, MAX_BIGNUM_WORDS);
    // Assign test values to BIGNUMs
    for (int i = 0; i < MAX_BIGNUM_WORDS; i++) {
        value_a.d[i] = A[i];
        value_n.d[i] = N[i];
    }
    // Find top
    value_a.top = find_top(&value_a, MAX_BIGNUM_WORDS);
    value_n.top = find_top(&value_n, MAX_BIGNUM_WORDS);
    // Print the test values
    bn_print("a: ", &value_a);
    bn_print("n: ", &value_n);
    // Test the bn_mod_inverse function
    bn_mod_inverse(&result, &value_a, &value_n);
    // Print the result
    bn_print("Modular inverse: ", &result);
    printf("\n");
}

// Main function
int main() {
    BN_ULONG test_values_a[][MAX_BIGNUM_WORDS] = {
        {0x3,0,0,0}, // 0
    };
    BN_ULONG test_values_n[][MAX_BIGNUM_WORDS] = {
        {0xB,0,0,0}, // 0
    };
    int num_tests = sizeof(test_values_a) / sizeof(test_values_a[0]);

    printf("\n\n### CUDA test:\n");

    BN_ULONG *d_A, *d_N;
    cudaMalloc((void**)&d_A, MAX_BIGNUM_WORDS * sizeof(BN_ULONG));
    cudaMalloc((void**)&d_N, MAX_BIGNUM_WORDS * sizeof(BN_ULONG));

    for (int i = 0; i < num_tests; i++) {
        printf("\nTest %d:\n", i);
        cudaMemcpy(d_A, test_values_a[i], MAX_BIGNUM_WORDS * sizeof(BN_ULONG), cudaMemcpyHostToDevice);
        cudaMemcpy(d_N, test_values_n[i], MAX_BIGNUM_WORDS * sizeof(BN_ULONG), cudaMemcpyHostToDevice);

        // Launch the kernel to run the test
        test<<<1, 1>>>(d_A, d_N);

        // Check for any errors after running the kernel
        cudaError_t err = cudaGetLastError();
        if (err != cudaSuccess) {
            printf("Error: %s\n", cudaGetErrorString(err));
            //return -1;
        }

        // Wait for GPU to finish before accessing on host
        cudaDeviceSynchronize();
    }

    cudaFree(d_A);
    cudaFree(d_N);
    return 0;
}
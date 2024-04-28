#include <stdio.h>
#include <cuda_runtime.h>
#include "bignum.h"

__global__ void kernel_test(BN_ULONG *A, BN_ULONG *B, int *sign_a, int *sign_b) {
    int success = 0;
    // Initialize values for each test
    BIGNUM a, b, result;
    init_zero(&a, MAX_BIGNUM_WORDS);
    init_zero(&b, MAX_BIGNUM_WORDS);
    init_zero(&result, MAX_BIGNUM_WORDS);

    a.top = MAX_BIGNUM_WORDS;
    b.top = MAX_BIGNUM_WORDS;
    result.top = MAX_BIGNUM_WORDS;

    // Assign test values and initialize top accordingly
    for (int i = 0; i < MAX_BIGNUM_WORDS; ++i) {
        a.d[i] = A[i];
        b.d[i] = B[i];
    }

    // Set the sign of the numbers
    a.neg = sign_a[0];
    b.neg = sign_b[0];

    bn_print("# a : ", &a);
    bn_print("# b : ", &b);

    // Test
    bn_add(&result, &a, &b);

    // Print results
    bn_print("# result: ", &result);
    printf("top: %d\n", result.top);
}

// Main function
int main() {
    BN_ULONG test_values_a[][MAX_BIGNUM_WORDS] = {
        {0xffffffffffffffff, 0xffffffffffffffff, 0,0}, // 0
        {0,0,0,0x1}, // 1
        {0xffffffffffffffff, 0,0,0}, // 2
        {0xffffffffffffffff, 0xffffffffffffffff, 0,0}, // 3
        {0x1234567890abcdef, 0,0,0}, // 4
        {0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff}, // 5
        {0x1234567890abcdef, 0,0,0}, // 6
        {0x1234567890abcdef, 0,0,0}, // 7
        {0x1234567890abcdef, 0,0,0}, // 8
        {0x1234567890abcdef, 0,0,0},  // 9
        {0x405000A0CA2248E1, 0xB788A1C84F4C756C, 0xAB7087E3F0C50175, 0xC17747B1566D9FE8}, //10
    };

    BN_ULONG test_values_b[][MAX_BIGNUM_WORDS] = {
        {0x1, 0,0,0}, // 0
        {0,0,0,0x2}, // 1
        {0x1, 0,0,0}, // 2
        {0x1, 0,0,0}, // 3
        {0,0,0,0}, // 4
        {0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff}, // 5
        {0x5678901234567890, 0,0,0}, // 6
        {0x5678901234567890, 0,0,0}, // 7
        {0xfedcba0987654321, 0,0,0}, // 8
        {0xfedcba0987654321, 0,0,0},  // 9
        {0x158A7E6564F93CDF, 0xD204BB99DD677993, 0xA7596D16B56D2AEF, 0x6C91CEA9CF0CAC55},  // 10
    };

    // Set sign to 0 for positive numbers, 1 for negative numbers
    int sign_a[] = {0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0};
    int sign_b[] = {0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0};

    int num_tests = sizeof(test_values_a) / sizeof(test_values_a[0]);

    printf("\n\n### CUDA test:\n");

    BN_ULONG *d_A, *d_B;
    int *d_sign_a, *d_sign_b;
    cudaMalloc((void**)&d_A, MAX_BIGNUM_WORDS * sizeof(BN_ULONG));
    cudaMalloc((void**)&d_B, MAX_BIGNUM_WORDS * sizeof(BN_ULONG));
    cudaMalloc((void**)&d_sign_a, sizeof(int));
    cudaMalloc((void**)&d_sign_b, sizeof(int));

    for (int i = 0; i < num_tests; i++) {
        printf("\nTest %d:\n", i);

        cudaMemcpy(d_A, test_values_a[i], MAX_BIGNUM_WORDS * sizeof(BN_ULONG), cudaMemcpyHostToDevice);
        cudaMemcpy(d_B, test_values_b[i], MAX_BIGNUM_WORDS * sizeof(BN_ULONG), cudaMemcpyHostToDevice);
        cudaMemcpy(d_sign_a, &sign_a[i], sizeof(int), cudaMemcpyHostToDevice);
        cudaMemcpy(d_sign_b, &sign_b[i], sizeof(int), cudaMemcpyHostToDevice);

        // Launch the kernel to run the test
        kernel_test<<<1, 1>>>(d_A, d_B, d_sign_a, d_sign_b);

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
    cudaFree(d_B);
    cudaFree(d_sign_a);
    cudaFree(d_sign_b);
    return 0;
}
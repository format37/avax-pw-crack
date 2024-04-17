#include <stdio.h>
#include <cuda_runtime.h>
#include "bignum.h"

__global__ void test_mod_inverse_kernel() {
    // Test values for 'a'
    BN_ULONG test_values_a[] = {
        0x3ULL,           // Test Case 1
        0x64ULL,          // Test Case 2: 100 in decimal
        0x1ULL,           // Test Case 3
        0x4ULL,           // Test Case 4
        0x100003ULL,       // Test Case 5: Simplified large number for demonstration
        0x123456789ABCDEFULL // Test Case 6: Large prime number
    };

    // 'n' values (ensure these are real prime numbers for valid tests, except where prime is not required)
    BN_ULONG test_values_n[] = {
        0xBULL,           // Test Case 1: 11 in decimal
        0x65ULL,          // Test Case 2: 101 in decimal
        0xDULL,           // Test Case 3: 13 in decimal
        0x8ULL,           // Test Case 4: Non-prime, to show no inverse exists
        0x100019ULL,       // Test Case 5: Simplified large prime number for demonstration
        0xFEDCBA987654323ULL // Test Case 6: Large prime number
    };

    // int num_tests = sizeof(test_values_a) / sizeof(test_values_a[0]);
    int num_tests = 1;

    for (int test = 0; test < num_tests; ++test) {
        // Check for errors and print results
        printf("\nTest %d:\n", test + 1);
        // Initialize BIGNUMs for testing
        BIGNUM a, n, inverse;
        init_zero(&a, MAX_BIGNUM_WORDS);
        init_zero(&n, MAX_BIGNUM_WORDS);
        init_zero(&inverse, MAX_BIGNUM_WORDS);

        // Initialize 'a' and 'n' with the test values
        a.d[0] = test_values_a[test];
        n.d[0] = test_values_n[test];

        // Find tops
        a.top = find_top(&a, MAX_BIGNUM_WORDS);
        n.top = find_top(&n, MAX_BIGNUM_WORDS);

        // Set neg
        a.neg = 0;
        n.neg = 0;

        bn_print("a: ", &a);
        bn_print("n: ", &n);

        bn_mod_inverse(&inverse, &a, &n);
        
        bn_print("modular inverse: ", &inverse);
    }

    printf("-- Finished test_mod_inverse_kernel --\n");
}

// Main function
int main() {
    BN_ULONG test_values_a[][MAX_BIGNUM_WORDS] = {
        {0,0,0,0x3}, // 0
    }
    BN_ULONG test_values_n[][MAX_BIGNUM_WORDS] = {
        {0,0,0,0xB}, // 0
    }
    int num_tests = sizeof(test_values_a) / sizeof(test_values_a[0]);

    printf("\n\n### CUDA test:\n");

    BN_ULONG *d_A, *d_B;
    cudaMalloc((void**)&d_A, MAX_BIGNUM_WORDS * sizeof(BN_ULONG));
    cudaMalloc((void**)&d_B, MAX_BIGNUM_WORDS * sizeof(BN_ULONG));

    for (int i = 0; i < num_tests; i++) {
        printf("\nTest %d:\n", i);

        cudaMemcpy(d_A, test_values_a[i], MAX_BIGNUM_WORDS * sizeof(BN_ULONG), cudaMemcpyHostToDevice);
        cudaMemcpy(d_B, test_values_b[i], MAX_BIGNUM_WORDS * sizeof(BN_ULONG), cudaMemcpyHostToDevice);

        // Launch the kernel to run the test
        test<<<1, 1>>>(d_A, d_B);

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
    return 0;
}
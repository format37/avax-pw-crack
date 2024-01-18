#include <stdio.h>
#include <cuda_runtime.h>
#include "bignum.h"

__global__ void test_bn_mul_kernel() {
    printf("++ test_bn_mul_kernel ++\n");
    // Multi-word and sign test cases
    BN_ULONG test_values_a[][MAX_BIGNUM_WORDS] = {
        {0x1ULL},
        {0xFULL},
        {0xFFULL},
        {0xABCULL},
        {0x1234567890ABCDEFULL},
        {0x10ULL},
        {0xFFFFFFFFFFFFFFFFULL},
        {0xFEDCBA0987654321ULL, 0x1234567890ABCDEFULL}
    };
    BN_ULONG test_values_b[][MAX_BIGNUM_WORDS] = {
        {0x2ULL},
        {0xFULL},
        {0x101ULL},
        {0x10ULL},
        {0xFEDCBA0987654321ULL},
        {0x10ULL},
        {0x1000000000000000ULL},
        {0xFEDCBA0987654321ULL, 0x1234567890ABCDEFULL}
    };

    int sign_a[] = {0, 0, 0, 0, 0, 0, 0, 0}; // Signs for 'a'
    int sign_b[] = {0, 0, 0, 0, 0, 0, 0, 1}; // Signs for 'b'

    int num_tests = sizeof(test_values_a) / sizeof(test_values_a[0]);

    for (int test = 0; test < num_tests; ++test) {
        printf("\nTest %d:\n", test + 1);
        // Initialize BIGNUMs for testing
        BIGNUM a, b, product;
        init_zero(&a, MAX_BIGNUM_WORDS);
        init_zero(&b, MAX_BIGNUM_WORDS);
        init_zero(&product, MAX_BIGNUM_WORDS);

        

        // Initialize 'a' and 'b' with the test values and set the top
        for (int i = 0; i < MAX_BIGNUM_WORDS; ++i) {
            a.d[i] = test_values_a[test][i];
            b.d[i] = test_values_b[test][i];
        }

        // Determine number of words for 'a' and 'b'
        a.top = find_top(&a, MAX_BIGNUM_WORDS);
        b.top = find_top(&b, MAX_BIGNUM_WORDS);
        
        // Set signs
        a.neg = sign_a[test];
        b.neg = sign_b[test];

        // Test bn_mul operation
        bn_mul(&a, &b, &product);

        // Update product's top
        product.top = find_top(&product, MAX_BIGNUM_WORDS);

        // Print the results
        bn_print("a: ", &a);
        bn_print("b: ", &b);
        bn_print("a * b = product: ", &product);
    }

    printf("-- Finished test_bn_mul_kernel --\n");
}

// Main function
int main() {
    printf("Starting bn_mul test\n");
    // Launch the kernel to run the test
    test_bn_mul_kernel<<<1, 1>>>();

    // Wait for GPU to finish before accessing on host
    cudaDeviceSynchronize();

    // Check for any errors after running the kernel
    cudaError_t err = cudaGetLastError();
    if (err != cudaSuccess) {
        printf("Error after running kernel: %s\n", cudaGetErrorString(err));
        return -1;
    }

    return 0;
}

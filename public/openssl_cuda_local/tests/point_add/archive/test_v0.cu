#include <stdio.h>
#include <cuda_runtime.h>
#include "bignum.h"

// Define your BIGNUM structure based on your project definitions
#define MAX_BIGNUM_WORDS 20
#define BN_ULONG unsigned long long int
#define BN_ULONG_NUM_BITS (sizeof(BN_ULONG)*8)

__global__ void test_mod_inverse_kernel() {
    printf("++ test_mod_inverse_kernel ++\n");

    // Test values similar to the ones used in your original bn_mod_inverse test
    BN_ULONG test_values_a[] = {
        0x123456789ABCDEFULL,
        0x1FFF3ULL,
        0x10001ULL
    };

    // 'n' values using prime numbers
    BN_ULONG test_values_n[] = {
        0xFEDCBA987654323ULL,   // prime number
        0x100000000000003ULL,   // prime number
        0x461ULL                // prime number
    };
    /*BN_ULONG test_values_a[] = {
        0x123456789ABCDEFULL
    };
    BN_ULONG test_values_n[] = {
        0xFEDCBA987654323ULL
    };*/


    int num_tests = sizeof(test_values_a) / sizeof(test_values_a[0]);

    for (int test = 0; test < num_tests; ++test) {
        // Initialize BIGNUMs for testing
        BIGNUM a, n, inverse;
        init_zero(&a, MAX_BIGNUM_WORDS);
        init_zero(&n, MAX_BIGNUM_WORDS);
        init_zero(&inverse, MAX_BIGNUM_WORDS);

        // Initialize 'a' and 'n' with the test values
        a.d[0] = test_values_a[test]; a.top = 1;
        n.d[0] = test_values_n[test]; n.top = 1;

        // Test bn_mod_inverse_fixed
        bn_mod_inverse_fixed(&inverse, &a, &n);

        // Print results
        printf("Test %d:\n", test + 1);
        bn_print("a: ", &a);
        bn_print("n: ", &n);
        bn_print("modular inverse: ", &inverse);
    }

    printf("-- Finished test_mod_inverse_kernel --\n");
}

// Main function
int main() {
    printf("Starting bn_mod_inverse test\n");
    // Launch the kernel to run the test
    test_mod_inverse_kernel<<<1, 1>>>();

    // Check for any errors after running the kernel
    cudaError_t err = cudaGetLastError();
    if (err != cudaSuccess) {
        printf("Error: %s\n", cudaGetErrorString(err));
        return -1;
    }

    // Wait for GPU to finish before accessing on host
    cudaDeviceSynchronize();
    return 0;
}
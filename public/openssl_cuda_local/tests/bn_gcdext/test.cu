#include <stdio.h>
#include <cuda_runtime.h>
#include "bignum.h"

// Define your BIGNUM structure based on your project definitions
#define MAX_BIGNUM_WORDS 20
#define BN_ULONG unsigned long long int
#define BN_ULONG_NUM_BITS (sizeof(BN_ULONG)*8)

__global__ void testKernel() {
    printf("++ testKernel for bn_gcdext ++\n");
    
    // Test cases like in C
    BN_ULONG test_values_a[] = {
        0x123456789ABCDEFULL,
        0x1FFF3ULL,
        0xFEDCBA9876543210ULL
    };
    
    BN_ULONG test_values_b[] = {
        0xFEDCBA987654321ULL,
        0x2468ACEULL,
        0xFEDCBA9876543210ULL
    };
    
    int num_tests = sizeof(test_values_a) / sizeof(test_values_a[0]);
    
    for (int test = 0; test < num_tests; ++test) {
        // Initialize BIGNUMs for testing
        BIGNUM a, b, g, s, t;
        init_zero(&a, MAX_BIGNUM_WORDS);
        init_zero(&b, MAX_BIGNUM_WORDS);
        init_zero(&g, MAX_BIGNUM_WORDS);
        init_zero(&s, MAX_BIGNUM_WORDS);
        init_zero(&t, MAX_BIGNUM_WORDS);

        // Initialize 'a' and 'b' with the test values
        a.d[0] = test_values_a[test]; a.top = 1;
        b.d[0] = test_values_b[test];  b.top = 1;

        // Test gcdext
        bn_gcdext(&g, &s, &t, &a, &b);

        // Print result
        printf("Test %d:\n", test + 1);
        bn_print("a: ", &a);
        bn_print("b: ", &b);
        bn_print("gcd: ", &g);
        bn_print("s: ", &s);
        bn_print("t: ", &t);
    }
    
    printf("-- Finished testKernel for bn_gcdext --\n");
}

// Main function
int main() {
    printf("Starting bn_gcdext test\n");
    // Launch the kernel to run the test
    testKernel<<<1, 1>>>();

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
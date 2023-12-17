#include <stdio.h>
#include <cuda_runtime.h>
#include "bignum.h"

// Define your BIGNUM structure based on your project definitions
#define MAX_BIGNUM_WORDS 20
#define BN_ULONG unsigned long long int
#define BN_ULONG_NUM_BITS (sizeof(BN_ULONG)*8)

// Test cases for bn_gcdext
__global__ void testKernel() {
    printf("++ testKernel for bn_gcdext ++\n");
    // Initialize BIGNUMs for testing
    BIGNUM a, b, g, s, t;
    init_zero(&a, MAX_BIGNUM_WORDS);
    init_zero(&b, MAX_BIGNUM_WORDS);
    init_zero(&g, MAX_BIGNUM_WORDS);
    init_zero(&s, MAX_BIGNUM_WORDS);
    init_zero(&t, MAX_BIGNUM_WORDS);

    // Initialize 'a' and 'b' with some values for gcd calculation
    // Choose arbitrary values for a and b here; for a real test, use meaningful values
    a.d[0] = 0x12345; a.top = 1;
    b.d[0] = 0x6789;  b.top = 1;

    // Test gcdext
    bn_gcdext(&g, &s, &t, &a, &b);

    // Print result
    printf("Testing bn_gcdext function:\n");
    bn_print("a: ", &a);
    bn_print("b: ", &b);
    bn_print("gcd: ", &g);
    bn_print("s: ", &s);
    bn_print("t: ", &t);
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
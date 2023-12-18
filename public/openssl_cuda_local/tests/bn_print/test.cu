#include <stdio.h>
#include <cuda_runtime.h>
#include "bignum.h"

__global__ void testPrintKernel() {
    printf("++ testPrintKernel for bn_print ++\n");

    // Single-word test
    BIGNUM num1;
    init_zero(&num1, MAX_BIGNUM_WORDS);
    num1.d[0] = 0x1F3; // Arbitrary value
    num1.top = 1;
    bn_print("Single word: ", &num1);

    // Multi-word test
    BIGNUM num2;
    init_zero(&num2, MAX_BIGNUM_WORDS);
    num2.d[0] = 0x12345678;
    num2.d[1] = 0x9ABCDEF0; // Another arbitrary value
    num2.top = 2;
    bn_print("Multi word: ", &num2);

    // Zero value test
    BIGNUM num3;
    init_zero(&num3, MAX_BIGNUM_WORDS);
    num3.top = 1; // Intentionally setting top non-zero to check print function
    bn_print("Zero value: ", &num3);

    printf("-- Finished testPrintKernel for bn_print --\n");
}

// Update the main test suite to include the print test
int main() {
    printf("Starting bn_print test\n");
    testPrintKernel<<<1, 1>>>();

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
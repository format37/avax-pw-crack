#include <stdio.h>
#include <cuda_runtime.h>
#define debug_print false
#include "bignum.h"

// Define your BIGNUM structure based on your project definitions
#define MAX_BIGNUM_WORDS 20
#define BN_ULONG unsigned long long int
#define BN_ULONG_NUM_BITS (sizeof(BN_ULONG) * 8)

// Test cases for bn_lshift_res
__global__ void testKernel() {
    printf("++ testKernel ++\n");
    // Initialize BIGNUMs for testing
    BIGNUM a, result;
    init_zero(&a, MAX_BIGNUM_WORDS);
    printf("## testKernel ##\n");
    init_zero(&result, MAX_BIGNUM_WORDS);
    

    BN_ULONG word = 0x1; // Starting with the value 1 for simplicity
    int shift_amounts[] = {1, 4, 16, 32, 64, 128}; // Different shift amounts to test
    
    // Example initialization for a single word can be adapted to your BIGNUM implementation
    a.top = 1;
    a.dmax = MAX_BIGNUM_WORDS;
    a.d[0] = word;
    
    // Zero out the other d elements if necessary
    for(int i = 1; i < a.dmax; ++i) {
        a.d[i] = 0;
    }
    printf("1 testKernel 1\n");
    // Run tests for different shift amounts
    for(int shift = 0; shift < sizeof(shift_amounts)/sizeof(shift_amounts[0]); ++shift) {
        // Reset result BIGNUM to zero for each test
        result.top = 0;
        result.dmax = a.dmax;
        for(int i = 0; i < result.dmax; ++i) {
            result.d[i] = 0;
        }

        // Test shifting the BIGNUM 'a' by 'shift_amounts[shift]' bits
        //bn_lshift_res_test(&result, &a, shift_amounts[shift]);
        bn_lshift_res(&result, &a, shift_amounts[shift]);
        
        // Print result, expected to see 'a' shifted left by 'shift' bits
        printf("Testing bn_lshift_res with shift_amount = %d\n", shift_amounts[shift]);
        bn_print("a: ", &a);
        bn_print("result: ", &result);
    }
    printf("-- testKernel --\n");
}


// Main function
int main() {
    printf("Starting\n");
    testKernel<<<1, 1>>>();
    cudaError_t err = cudaGetLastError();
    if (err != cudaSuccess) {
        printf("Error: %s\n", cudaGetErrorString(err));
        return -1;
    }
    cudaDeviceSynchronize();
    return 0;
}

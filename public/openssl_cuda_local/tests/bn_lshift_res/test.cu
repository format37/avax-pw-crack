#include <stdio.h>
#include <cuda_runtime.h>
#include "bignum.h"

// Define your BIGNUM structure based on your project definitions
#define MAX_BIGNUM_WORDS 20
#define BN_ULONG unsigned long long int
#define BN_ULONG_NUM_BITS (sizeof(BN_ULONG) * 8)

typedef struct {
    int top; // Number of significant words
    int dmax; // Maximum number of words
    BN_ULONG d[MAX_BIGNUM_WORDS]; // Storage for BIGNUM digits (words)
} BIGNUM;

// BIGNUM utility functions need to be implemented according to your definitions:
__device__ void bn_set_word(BIGNUM *bn, BN_ULONG w);
__device__ void bn_print(char *label, BIGNUM *bn);
__device__ void bn_copy(BIGNUM *dest, const BIGNUM *src);

// Put your bn_lshift_res function here (as you provided with debugging prints)
__device__ void bn_lshift_res(BIGNUM *result, BIGNUM *a, int shift) {
    if (shift <= 0) {
        // No shift or invalid shift count; copy input to output with no modifications.
        bn_copy(result, a);
        printf("bn_lshift_res 0\n");
        return;
    }

    // Initialize result BIGNUM according to your BIGNUM structure definition
    // Make sure that result->d has enough space to hold the result

    // Perform the shift for each word from the least significant upwards.
    BN_ULONG carry = 0;
    for (int i = 0; i < a->top; ++i) {
        printf("bn_lshift_res [%d]\n", i);
        bn_print("a: ", a);        
        BN_ULONG new_carry = a->d[i] >> (BN_ULONG_NUM_BITS - shift); // Capture the bits that will be shifted out.
        printf("new_carry: %llu\n", new_carry);
        result->d[i] = (a->d[i] << shift) | carry; // Shift current word and add bits from previous carry.
        printf("result->d[i]: %llu\n", result->d[i]);
        carry = new_carry; // Update carry for the next iteration.
    }

    // Assign the carry to the new most significant word if needed.
    if (carry != 0) {
        printf("bn_lshift_res 1\n");
        bn_print("result 0: ", result);
        result->d[a->top] = carry; // Assign the carry to the new most significant word.
        printf("result->d[a->top]: %llu\n", result->d[a->top]);
        result->top = a->top + 1;
        printf("result->top: %d\n", result->top);
    } else {
        printf("bn_lshift_res 2\n");
        bn_print("result 1: ", result);
        result->top = a->top;
        printf("result->top: %d\n", result->top);
    }

    // Initialize any remaining higher-order words to zero if necessary
    // This depends on the internals of your BIGNUM structure.
    for (int i = result->top; i < result->dmax; ++i) {
        result->d[i] = 0;
    }
    printf("bn_lshift_res 3\n");
}

// Test cases for bn_lshift_res
__global__ void testKernel() {
    // Initialize BIGNUMs for testing
    BIGNUM a, result;
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
    
    // Run tests for different shift amounts
    for(int shift = 0; shift < sizeof(shift_amounts)/sizeof(shift_amounts[0]); ++shift) {
        // Reset result BIGNUM to zero for each test
        result.top = 0;
        result.dmax = a.dmax;
        for(int i = 0; i < result.dmax; ++i) {
            result.d[i] = 0;
        }

        // Test shifting the BIGNUM 'a' by 'shift_amounts[shift]' bits
        bn_lshift_res(&result, &a, shift_amounts[shift]);
        
        // Print result, expected to see 'a' shifted left by 'shift' bits
        printf("Testing bn_lshift_res with shift_amount = %d\n", shift_amounts[shift]);
        bn_print("a: ", &a);
        bn_print("result: ", &result);
    }
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

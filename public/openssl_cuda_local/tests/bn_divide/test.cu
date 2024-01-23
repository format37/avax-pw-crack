#include <stdio.h>
#include <cuda_runtime.h>
#include "bignum.h"

// Test kernel for bn_divide
__global__ void testKernel() {
    printf("++ testKernel for bn_divide ++\n");
    // Set the maximum number of test cases
    /*const int num_tests = 1;  // Updated number of tests
    int word_num[num_tests] = {2};
    BN_ULONG test_values_dividend[][MAX_BIGNUM_WORDS] = {
        {0x1234567890ABCDEF, 0x1234567890ABCDEF} // Example values for A
        }; 
    BN_ULONG test_values_divisor[][MAX_BIGNUM_WORDS] = {
        {0, 0x2} // Example values for B
        };*/
    
    const int num_tests = 6;  // Updated number of tests
    // Initialize the word_num array
    int word_num[num_tests] = {1, 1, 1, 1, 1, 2};

    BN_ULONG test_values_dividend[][MAX_BIGNUM_WORDS] = {
        {0x1}, // Test 1
        {0xF}, // Test 2
        {0xF}, // Test 3
        {0x17}, // Test 4
        {0x1234567890ABCDEF}, // Test 5
        {0x1234567890ABCDEF, 0x1234567890ABCDEF} // Test 6
    };

    BN_ULONG test_values_divisor[][MAX_BIGNUM_WORDS] = {
        {0x2}, // 1
        {0xF}, // 2
        {0x1}, // 3
        {0x5}, // 4
        {0x1}, // 5
        {0, 0x2} // 6
    };
    
    // Initialize 'dividend' and 'divisor' with test values for each test
    for (int test = 0; test < num_tests; ++test) {
        printf("\nTest %d:\n", test + 1);
        BIGNUM dividend, divisor, quotient, remainder;
        init_zero(&dividend, MAX_BIGNUM_WORDS);
        init_zero(&divisor, MAX_BIGNUM_WORDS);
        init_zero(&quotient, MAX_BIGNUM_WORDS);
        init_zero(&remainder, MAX_BIGNUM_WORDS);
        
        // Assign test values to 'dividend' and 'divisor', and initialize top accordingly
        for (int i = 0; i < MAX_BIGNUM_WORDS; ++i) {
            dividend.d[i] = test_values_dividend[test][i];
            divisor.d[i] = test_values_divisor[test][i];
        }
        
        dividend.top = word_num[test];
        divisor.top = word_num[test];

        divisor.neg = 1;

        // Test division
        bn_divide(&quotient, &remainder, &dividend, &divisor);
        /*int dividend_bits[BN_ULONG_NUM_BITS * 2];
        int divisor_bits[BN_ULONG_NUM_BITS * 2];
        // Convert BIGNUM dividend to binary array 
        for(int i = 0; i < dividend.top; ++i) {
            convert_word_to_binary(dividend.d[i], dividend_bits + i*BN_ULONG_NUM_BITS); 
        }
        // Same for divisor 
        for(int i = 0; i < divisor.top; ++i) {
            convert_word_to_binary(divisor.d[i], divisor_bits + i*BN_ULONG_NUM_BITS);
        }
        int quotient_bits[BN_ULONG_NUM_BITS * 2];
        int remainder_bits[BN_ULONG_NUM_BITS * 2];
        // Binary divide
        binary_divide(dividend_bits, divisor_bits, quotient_bits, remainder_bits);
        // Convert quotient binary to BIGNUM
        for(int i = 0; i < MAX_BIGNUM_WORDS; ++i) {
            quotient.d[i] = convert_binary_to_word(quotient_bits + i*BN_ULONG_NUM_BITS);
        }
        // Same for remainder
        for(int i = 0; i < MAX_BIGNUM_WORDS; ++i) {
            remainder.d[i] = convert_binary_to_word(remainder_bits + i*BN_ULONG_NUM_BITS); 
        }*/

        // Print results        
        bn_print("dividend : ", &dividend);
        bn_print("divisor  : ", &divisor);
        bn_print("quotient : ", &quotient);
        bn_print("remainder: ", &remainder);
    }
    printf("-- Finished testKernel for bn_divide --\n");
}

// Main function
int main() {
    printf("Starting bn_divide test\n");
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
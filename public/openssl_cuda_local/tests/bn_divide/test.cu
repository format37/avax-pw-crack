#include <stdio.h>
#include <cuda_runtime.h>
#include "bignum.h"

// Test kernel for bn_divide
__global__ void testKernel() {
    printf("++ testKernel for bn_divide ++\n");
    // Set the maximum number of test cases
    
    const int num_tests = 6;  // Updated number of tests
    // Initialize the word_num array
    //int word_num[num_tests] = {4};
    int word_num[num_tests] = {4, 4, 1, 1, 1, 2};
    //int word_num[num_tests] = {1, 1, 1, 1, 1, 2, 1};
    //int word_num[num_tests] = {1, 1, 1, 1, 1, 1};

    BN_ULONG test_values_dividend[][MAX_BIGNUM_WORDS] = {
        
        {0x1,0,0,0}, // Test 1
        {0xF,0,0,0}, // Test 2
        {0xF}, // Test 3
        {0x17}, // Test 4
        {0x1234567890ABCDEF}, // Test 5
        {0x7234567890ABCDEF, 0x1234567890ABCDEF}, // Test 6 - Bignum reverse. Actually this is 0x1234567890ABCDEF7234567890ABCDEF
        {0xB}
    };

    BN_ULONG test_values_divisor[][MAX_BIGNUM_WORDS] = {
        
        {0x2,0,0,0}, // 1
        {0xF,0,0,0}, // 2
        {0x1}, // 3
        {0x5}, // 4
        {0x1}, // 5
        {0x2, 0}, // 6 - Bignum reverse. Actually this is 0x2
        {0x3}
    };
    int success = 0;
    
    // Initialize 'dividend' and 'divisor' with test values for each test
    for (int test = 0; test < num_tests; ++test) {
        printf("\nTest %d:\n", test + 1);
        BIGNUM dividend, divisor, quotient, remainder;
        init_zero(&dividend, MAX_BIGNUM_WORDS);
        init_zero(&divisor, MAX_BIGNUM_WORDS);
        init_zero(&quotient, MAX_BIGNUM_WORDS);
        init_zero(&remainder, MAX_BIGNUM_WORDS);
        
        dividend.top = word_num[test];
        divisor.top = word_num[test];

        // Assign test values to 'dividend' and 'divisor', and initialize top accordingly
        for (int i = 0; i < word_num[test]; ++i) {
            dividend.d[i] = test_values_dividend[test][i];
            divisor.d[i] = test_values_divisor[test][i];
        }

        // divisor.neg = 1;
        
        // Test division
        success = bn_divide_rev3(&quotient, &remainder, &dividend, &divisor);
        //bn_divide(&quotient, &remainder, &dividend, &divisor);
        //break;

        // Print results        
        bn_print("dividend : ", &dividend);
        bn_print("divisor  : ", &divisor);
        bn_print("quotient : ", &quotient);
        bn_print("remainder: ", &remainder);
        //break;
    }
    printf("-- Finished testKernel for bn_divide --\n");
}

// Main function
int main() {
    // Print BN_ULONG_NUM_BITS using %zu for size_t
    printf("BN_ULONG_NUM_BITS: %d\n", BN_ULONG_NUM_BITS);

    // If you also want to print the size of BN_ULONG, you can do it like this:
    printf("Size of BN_ULONG: %zu bytes\n", sizeof(BN_ULONG));

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
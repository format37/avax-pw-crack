#include <stdio.h>
#include <cuda_runtime.h>
#include "bignum.h"

// Define your BIGNUM structure based on your project definitions
#define MAX_BIGNUM_WORDS 20
#define BN_ULONG unsigned long long int
#define BN_ULONG_NUM_BITS (sizeof(BN_ULONG) * 8)

// Test kernel for bn_divide
__global__ void testKernel() {
    printf("++ testKernel for bn_divide ++\n");
    // Set the maximum number of test cases
    const int num_tests = 7;  // Updated number of tests

    // Updated Test values for 'dividend' and 'divisor' with leading zero words
    BN_ULONG test_values_dividend[num_tests][MAX_BIGNUM_WORDS] = {
        {0x1},
        {0xF},
        {0xF},
        {0x17}, // 23 in decimal
        {0x1234567890ABCDEF, 0xFEDCBA0987654321}, // Multi-word dividend
        {0x0, 0xFEDCBA0987654321}, // Dividend with leading zero word
        {0x0, 0x0, 0xFEDCBA0987654321} // Dividend with more leading zero words
    };

    BN_ULONG test_values_divisor[num_tests][MAX_BIGNUM_WORDS] = {
        {0x2},
        {0xF},
        {0x1},
        {0x5}, // 5 in decimal
        {0x1, 0x1}, // Multi-word divisor
        {0x0, 0x1}, // Divisor with leading zero word
        {0x0, 0x0, 0x1} // Divisor with more leading zero words
    };

    // Initialize the word_num array
    int word_num[num_tests] = {1, 1, 1, 1, 2, 2, 3};

    // Initialize 'dividend' and 'divisor' with test values for each test
    for (int test = 0; test < num_tests; ++test) {
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

        // Update top for new test cases
        /*if (test >= 5) {
            dividend.top = 3; // Adjust based on the number of words in use
            divisor.top = 3;  // Adjust based on the number of words in use
        } else {
            dividend.top = (test < 4) ? 1 : 2;
            divisor.top = (test < 4) ? 1 : 2;
        }*/
        if (test == 5) {
            dividend.top = 2; // Adjust based on the number of words including leading zeros
            divisor.top = 2;
        } else if (test == 6) {
            dividend.top = 3;
            divisor.top = 3;
        } else {
            dividend.top = word_num[test];
            divisor.top = word_num[test];
        }
        //divisor.top = word_num[test];
        //dividend.top = word_num[test];

        // Test division
        bn_divide(&quotient, &remainder, &dividend, &divisor);

        // Print results
        printf("Test %d:\n", test + 1);
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
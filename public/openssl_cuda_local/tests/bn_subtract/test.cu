#include <stdio.h>
#include <cuda_runtime.h>
#include "bignum.h"
//#include "bignum_test.h"

// Define your BIGNUM structure based on your project definitions
//#define MAX_BIGNUM_WORDS 20
//#define MAX_BIGNUM_WORDS 4
//#define BN_ULONG unsigned long long int
//#define BN_ULONG_NUM_BITS (sizeof(BN_ULONG) * 8)

// Test kernel for bn_subtract
__global__ void testKernel() {
    printf("++ testKernel for bn_subtract ++\n");

    // Define test cases for simplified debugging
    const int num_tests = 7; // Update this based on the number of tests you're running

    // Test values for 'a'
    BN_ULONG test_values_a[7][MAX_BIGNUM_WORDS] = {
        {0x1}, // Test case 1: Equal values
        {0x8}, // Test case 2: Simple subtraction without borrowing
        {0x100000000}, // Test case 3: Borrowing from a single higher word
        {0x1000000000000}, // Test case 4: Borrowing across multiple words 
        {0x1000000000000000, 0x0}, // Test case 5: Zero high words trimmed in result
        {0x123456789ABCDEF0}, // Test case 6: Large number subtraction
        {0x0} // Test case 7: Underflow error
    };

    // Test values for 'b' 
    BN_ULONG test_values_b[7][MAX_BIGNUM_WORDS] = {
        {0x1}, // Test case 1: Equal values 
        {0x5}, // Test case 2: Simple subtraction without borrowing
        {0x1}, // Test case 3: Borrowing from a single higher word
        {0x1}, // Test case 4: Borrowing across multiple words
        {0x1}, // Test case 5: Zero high words trimmed in result 
        {0xFEDCBA9876543210}, // Test case 6: Large number subtraction
        {0x1} // Test case 7: Underflow error
    };
  
    // Run tests
    for (int test = 0; test < num_tests; ++test) {
        printf("\nTest %d:\n", test + 1);
        BIGNUM a, b, result;
        init_zero(&a, MAX_BIGNUM_WORDS);
        init_zero(&b, MAX_BIGNUM_WORDS);
        init_zero(&result, MAX_BIGNUM_WORDS);

        // Assign test values to 'a' and 'b', and initialize top accordingly
        for (int i = 0; i < MAX_BIGNUM_WORDS; ++i) {
            a.d[i] = test_values_a[test][i];
            b.d[i] = test_values_b[test][i];
        }
        a.top = find_top(&a, MAX_BIGNUM_WORDS);
        b.top = find_top(&b, MAX_BIGNUM_WORDS);

        // Perform the subtraction
        bn_subtract(&result, &a, &b);

        // Update result.top
        result.top = find_top(&result, MAX_BIGNUM_WORDS);

        // Print results
        bn_print("a: ", &a);
        bn_print("b: ", &b);
        bn_print("a - b: ", &result);
    }

    printf("-- Finished testKernel for bn_subtract --\n");
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
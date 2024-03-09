#include <stdio.h>
#include <cuda_runtime.h>
#include "bignum.h"

// Define your BIGNUM structure based on your project definitions
/*#define MAX_BIGNUM_WORDS 20
#define BN_ULONG unsigned long long int
#define BN_ULONG_NUM_BITS (sizeof(BN_ULONG)*8)*/
#define TEST_BIGNUM_WORDS 1 // Adjust based on the highest number of words needed

__global__ void test_mod_inverse_kernel() {
    printf("++ test_mod_inverse_kernel ++\n");

    // Test values for 'a'
    BN_ULONG test_values_a[] = {
        0x3ULL,           // Test Case 1
        0x64ULL,          // Test Case 2: 100 in decimal
        0x1ULL,           // Test Case 3
        0x4ULL,           // Test Case 4
        0x100003ULL,       // Test Case 5: Simplified large number for demonstration
        0x123456789ABCDEFULL // Test Case 6: Large prime number
    };

    // 'n' values (ensure these are real prime numbers for valid tests, except where prime is not required)
    BN_ULONG test_values_n[] = {
        0xBULL,           // Test Case 1: 11 in decimal
        0x65ULL,          // Test Case 2: 101 in decimal
        0xDULL,           // Test Case 3: 13 in decimal
        0x8ULL,           // Test Case 4: Non-prime, to show no inverse exists
        0x100019ULL,       // Test Case 5: Simplified large prime number for demonstration
        0xFEDCBA987654323ULL // Test Case 6: Large prime number
    };

    // int num_tests = sizeof(test_values_a) / sizeof(test_values_a[0]);
    int num_tests = 1;

    for (int test = 0; test < num_tests; ++test) {
        // Check for errors and print results
        printf("\nTest %d:\n", test + 1);
        // Initialize BIGNUMs for testing
        BIGNUM a, n, inverse;
        init_zero(&a, MAX_BIGNUM_WORDS);
        init_zero(&n, MAX_BIGNUM_WORDS);
        init_zero(&inverse, MAX_BIGNUM_WORDS);

        // Print tops
        //printf("a->top: %d\n", a.top);
        //printf("n->top: %d\n", n.top);

        // Initialize 'a' and 'n' with the test values
        a.d[0] = test_values_a[test];
        n.d[0] = test_values_n[test];

        // Find tops
        a.top = find_top(&a, MAX_BIGNUM_WORDS);
        n.top = find_top(&n, MAX_BIGNUM_WORDS);

        // Set neg
        a.neg = 0;
        n.neg = 0;

        // Print tops
        //printf("a->top: %d\n", a.top);
        //printf("n->top: %d\n", n.top);

        bn_print("a: ", &a);
        bn_print("n: ", &n);

        bn_mod_inverse_7(&inverse, &a, &n);
        //bn_mod_inverse_6(&inverse, &a, &n);
        //bn_mod_inverse_4(&inverse, &a, &n);
        //bn_mod_inverse_5_claude(&inverse, &a, &n);

        //bn_mod_inverse_3(&inverse, &a, &n);

        //bn_mod_inverse_2(&inverse, &a, &n);
        /*Initial Value u: 123456789abcdef
        Initial Value v: fedcba987654323
        Final Value x1: 0
        Final Values v: f000000000000000
        Inverse does not exist.
        modular inverse: 0*/

        // bn_mod_inverse(&inverse, &a, &n);
        //modular inverse: 0
        
        // bn_mod_inverse_claude(&inverse, &a, &n);
        // Stuck in an infinite loop
        
        // bn_mod_inverse_fixed(&inverse, &a, &n);
        /*a: 123456789abcdef
        n: fedcba987654323
        ++ bn_mod_inverse_fixed ++
        Error: Underflow in subtraction, result is invalid.
        Error: Underflow in subtraction, result is invalid.
        Error: Underflow in subtraction, result is invalid.
        Error: Underflow in subtraction, result is invalid.
        Error: Underflow in subtraction, result is invalid.
        s: 0
        n: fedcba987654323
        NOT bn_is_negative(&s) -- bn_mod_inverse_fixed --
        modular inverse: 0*/
        
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
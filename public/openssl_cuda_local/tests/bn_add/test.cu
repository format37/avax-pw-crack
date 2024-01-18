#include <stdio.h>
#include <cuda_runtime.h>
#include "bignum.h"

// Define your BIGNUM structure based on your project definitions
/*#define MAX_BIGNUM_WORDS 20
#define BN_ULONG unsigned long long int
#define BN_ULONG_NUM_BITS (sizeof(BN_ULONG) * 8)*/

// Function prototypes for the bn_add function test
// __device__ void bn_add(BIGNUM *a, BIGNUM *b, BIGNUM *r);

// Test kernel for bn_add
__global__ void testKernel() {
    printf("++ testKernel for bn_add ++\n");

    // Set the maximum number of test cases
    const int num_tests = 7;

    // 10 + -5 = 5 # sub 10 - 5
    // 10 + -10 = 0 # sub 10 - 10
    // 10 + -15 = -5 # sub 15 - 10
    // -10 + -5 = -15 # add 10 + 5
    // -10 + 5 = -5 # sub 10 - 5
    // -10 + 15 = 5 # sub 15 - 10

    // Test values for 'a' and 'b'
    BN_ULONG test_values_a[num_tests][MAX_BIGNUM_WORDS] = {
        {0x1},
        {0xFFFFFFFFFFFFFFFF},
        {0x0, 0x1}, // Representing 1 << 64 (2^64)
        {0x0, 0xFFFFFFFFFFFFFFFF}, // test 4
        {0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF}, // test 5: -1 in two's complement (two words)
        {0x1, 0xFFFFFFFFFFFFFFFF}, // test 6: Negative number with two words
        {0x1, 0x0} // test 7
    };

    BN_ULONG test_values_b[num_tests][MAX_BIGNUM_WORDS] = {
        {0x2},
        {0x1},
        {0x0, 0x2}, // Representing 2 << 64 (2^65)
        {0xFFFFFFFFFFFFFFFF, 0x1}, // test 4
        {0x1, 0x0}, // test 5: -1 in two's complement (two words)
        {0xFFFFFFFFFFFFFFFF, 0x0}, // test 6
        {0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFFF} // test 7: -2 in two's complement (two words)
    };

    int bn_signs_a[num_tests] = {
        0, //test 1
        0, //test 2
        0, //test 3
        0, //test 4
        0, //test 5
        1, //test 6
        0 //test 7
    };

    int bn_signs_b[num_tests] = {
        0, //test 1
        0, //test 2
        0, //test 3
        0, //test 4
        1, //test 5
        0, //test 6
        1 //test 7
    };
    /*
    // Test values for 'a' and 'b'
    BN_ULONG test_values_a[num_tests][MAX_BIGNUM_WORDS] = {
        {0xA}, // 10
        {0xA}, // 10
        {0xF}, // 15
        {0xA}, // -10 (by sign)
        {0xA}, // -10 (by sign)
        {0xA}  // -10 (by sign)
    };
    // Signs for 'a' and 'b'
    int bn_signs_a[num_tests] = {
        0, // +10
        0, // +10
        0, // +15
        1, // -10
        1, // -10
        1  // -10
    };

    BN_ULONG test_values_b[num_tests][MAX_BIGNUM_WORDS] = {
        {0x5}, // -5 (by sign)
        {0xA}, // -10 (by sign)
        {0xA}, // 10
        {0x5}, // -5 (by sign)
        {0x5}, // 5
        {0xF}  // 15
    };

    int bn_signs_b[num_tests] = {
        1, // -5
        1, // -10
        0, // +10
        1, // -5
        0, // +5
        0  // +15
    };*/


    // Initialize 'a' and 'b' with test values for each test
    for (int test = 0; test < num_tests; ++test) {
        printf("\nTest %d:\n", test + 1);

        BIGNUM a, b, result;
        init_zero(&a, MAX_BIGNUM_WORDS);
        init_zero(&b, MAX_BIGNUM_WORDS);
        init_zero(&result, MAX_BIGNUM_WORDS);

        // Assign test values to 'a' and 'b', and initialize top accordingly
        for (int i = 0; i < MAX_BIGNUM_WORDS; ++i) {
            a.d[i] = test_values_a[test][i];
            a.neg = bn_signs_a[test];
            b.d[i] = test_values_b[test][i];
            b.neg = bn_signs_b[test];
        }
        a.top = find_top(&a, MAX_BIGNUM_WORDS);
        b.top = find_top(&b, MAX_BIGNUM_WORDS);

        // Test addition
        bn_add(&result, &a, &b);

        // Print results
        bn_print("a     : ", &a);
        bn_print("b     : ", &b);
        bn_print("result: ", &result);
    }

    printf("-- Finished testKernel for bn_add --\n");
}

// Main function
int main() {
    printf("Starting bn_add test\n");
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
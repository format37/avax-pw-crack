#include <stdio.h>
#include <cuda_runtime.h>
#include "bignum.h"
//#include "bignum_test.h"

// Test kernel for bn_subtract
__global__ void testKernel() {
    printf("++ testKernel for bn_subtract ++\n");

    // Define test cases for simplified debugging
    const int num_tests = 11; // Update this based on the number of tests you're running

    BN_ULONG test_values_a[num_tests][MAX_BIGNUM_WORDS] = {
        {0x1}, // 1: neg - neg
        {0x1}, // 2: pos - neg
        {0x1}, // 3: neg - pos
        {0x4}, // 4: neg - pos
        {0x4}, // 5: pos - neg
        {0x1}, // 6: neg - pos
        {0x1},  // 7: pos - neg
        {0x1, 0x0},                // 8: Two-word positive-neg test case (low word, high word)
        {0xFFFFFFFFFFFFFFFF, 0x1},  // 9: Two-word neg-pos overflow test case (low word, high word)
        {0x0}, // 0 - pos
        {0x0}, // 0 - neg
    };
    int negative_a[num_tests] = {
        1, // 1: neg - neg
        0, // 2: pos - neg
        1, // 3: neg - pos
        1, // 4: neg - pos
        0, // 5: pos - neg
        1, // 6: neg - pos
        0,  // 7: pos - neg
        0,  // 8: pos
        1,   // 9: neg
        0, // 0 - pos
        0, // 0 - neg
    };
    BN_ULONG test_values_b[num_tests][MAX_BIGNUM_WORDS] = {
        {0x1}, // 1: neg - neg
        {0x1}, // 2: pos - neg
        {0x1}, // 3: neg - pos
        {0x1}, // 4: neg - pos
        {0x1}, // 5: pos - neg
        {0x4}, // 6: neg - pos
        {0x4},  // 7: pos - neg
        {0x2, 0x0},                // 8: Two-word negative-neg test case (low word, high word)
        {0x1, 0x0},                 // 9: Two-word pos-neg overflow test case (low word, high word)
        {0x1}, // 0 - pos
        {0x1}, // 0 - neg
    };
    int negative_b[num_tests] = {
        1, // 1: neg - neg
        1, // 2: pos - neg
        0, // 3: neg - pos
        0, // 4: neg - pos
        1, // 5: pos - neg
        0, // 6: neg - pos
        1,  // 7: pos - neg
        1,  // 8: neg
        0,   // 9: pos
        0, // 0 - pos
        1, // 0 - neg
    };

    // Test values for 'a'
    /*BN_ULONG test_values_a[num_tests][MAX_BIGNUM_WORDS] = {
        {0x1}, // Test case 1: Equal values
        {0x8}, // Test case 2: Simple subtraction without borrowing
        {0x100000000}, // Test case 3: Borrowing from a single higher word
        {0x1000000000000}, // Test case 4: Borrowing across multiple words 
        {0x1000000000000000, 0x0}, // Test case 5: Zero high words trimmed in result
        {0x123456789ABCDEF0}, // Test case 6: Large number subtraction
        {0x0}, // Test case 7: Underflow error
        {0x1, 0x1},                           // Test case 8: Simple 2-word subtraction without borrowing
        {0xFFFFFFFFFFFFFFF1, 0x000000000000000F},            // Test case 9: Max value in lower word
        {0xFFFFFFFFFFFFFFFF, 0x1},            // Test case 10: Carry from lower to upper word
        {0xFFFFFFFFFFFFFFFF, 0x100000000},    // Test case 11: Large value spanning two words
        {0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF} // Test case 12: Max 2-word value
    };

    // Test values for 'b' 
    BN_ULONG test_values_b[num_tests][MAX_BIGNUM_WORDS] = {
        {0x1}, // Test case 1: Equal values 
        {0x5}, // Test case 2: Simple subtraction without borrowing
        {0x1}, // Test case 3: Borrowing from a single higher word
        {0x1}, // Test case 4: Borrowing across multiple words
        {0x1}, // Test case 5: Zero high words trimmed in result 
        {0xFEDCBA9876543210}, // Test case 6: Large number subtraction
        {0x1}, // Test case 7: Underflow error
        {0x1, 0x0},                           // Test case 8: Simple 2-word subtraction without borrowing
        {0xFFFFFFFFFFFFFFFF, 0x0000000000000000},            // Test case 9: Max value in lower word
        {0xFFFFFFFFFFFFFFFF, 0x0},            // Test case 10: Carry from lower to upper word
        {0xFFFFFFFFFFFFFFFF, 0x0},            // Test case 11: Large value spanning two words
        {0x1, 0x0}                            // Test case 12: Max 2-word value
    };*/

  
    // Run tests
    for (int test = 0; test < num_tests; ++test) {
        printf("\nTest %d:\n", test + 1);
        BIGNUM a, b, result;
        init_zero(&a, MAX_BIGNUM_WORDS);
        // Set sign of 'a' based on test case
        if (negative_a[test]) {
            a.neg = 1;
        }
        init_zero(&b, MAX_BIGNUM_WORDS);
        // Set sign of 'b' based on test case
        if (negative_b[test]) {
            b.neg = 1;
        }
        init_zero(&result, MAX_BIGNUM_WORDS);

        // Assign test values to 'a' and 'b', and initialize top accordingly
        for (int i = 0; i < MAX_BIGNUM_WORDS; ++i) {
            a.d[i] = test_values_a[test][i];
            // printf("* a.d[%d]: %lx\n", i, a.d[i]);
            b.d[i] = test_values_b[test][i];
            // printf("* b.d[%d]: %lx\n", i, b.d[i]);
        }
        a.top = find_top(&a, MAX_BIGNUM_WORDS);
        b.top = find_top(&b, MAX_BIGNUM_WORDS);
        bn_print("a: ", &a);
        bn_print("b: ", &b);

        // Perform the subtraction
        bn_subtract(&result, &a, &b);

        // Update result.top
        result.top = find_top(&result, MAX_BIGNUM_WORDS);

        // Print results
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
#include <stdio.h>
#include <cuda_runtime.h>
#define debug_print false
#include "bignum.h"

// Define your BIGNUM structure based on your project definitions
#define MAX_BIGNUM_WORDS 20
#define BN_ULONG unsigned long long int
#define BN_ULONG_NUM_BITS (sizeof(BN_ULONG) * 8)


__global__ void testKernel() {
    printf("++ testKernel for bn_cmp ++\n");
    
    // Define some test values
    BN_ULONG test_values[][MAX_BIGNUM_WORDS] = {
        {0x1}, // Single word, small value
        {0x0, 0x1}, // Two words with leading zero
        {0xFFFFFFFFFFFFFFFFULL}, // Single word, maximal value
        {0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL}, // Two words, maximal value
        {0xFFFFFFFFFFFFFFFFULL, 0x0}, // Two words, with trailing zero
    };
    
    // Define the number of test cases based on our test values array
    const int num_tests = sizeof(test_values) / sizeof(test_values[0]);

    // Comparisons to perform - each pair indexes into the test_values
    int comparison_indices[][2] = {
        {0, 0}, // Compare same value
        {0, 1}, // Compare value with a version with leading zero
        {1, 0}, // Reverse of the above comparison
        {2, 3}, // Compare a single max word with a double max word value
        {3, 2}, // Reverse of the above comparison
        {2, 4}, // Compare max word against same value but with trailing zero
        {4, 2}, // Reverse of the above comparison
        {0, 2}, // Compare small value with maximal single word value
        {2, 0}, // Reverse of the above comparison
    };

    // Function to determine the appropriate 'top' value
    auto get_top = [](const unsigned long *value, int max_words) -> int {
        int i;
        for (i = max_words - 1; i >= 0; i--) {
            if (value[i] != 0) {
                return i + 1; // Return the index of the highest non-zero word plus one
            }
        }
        return 0; // If all zeros, the top is 0
    };

    // Run through test value comparisons
    for (int i = 0; i < sizeof(comparison_indices) / sizeof(comparison_indices[0]); ++i) {
        BIGNUM a, b;
        init_zero(&a, MAX_BIGNUM_WORDS);
        init_zero(&b, MAX_BIGNUM_WORDS);

        // Initialize BIGNUM a
        for (int j = 0; j < MAX_BIGNUM_WORDS; ++j) {
            a.d[j] = test_values[comparison_indices[i][0]][j];
        }
        a.top = get_top(a.d, MAX_BIGNUM_WORDS); // Set the appropriate value based on the significant bits of a
        
        // Initialize BIGNUM b
        for (int j = 0; j < MAX_BIGNUM_WORDS; ++j) {
            b.d[j] = test_values[comparison_indices[i][1]][j];
        }
        b.top = get_top(b.d, MAX_BIGNUM_WORDS); // Set the appropriate value based on the significant bits of b

        // Now compare a and b using bn_cmp
        int cmp_result = bn_cmp(&a, &b);

        // Print results
        printf("Comparing a and b:\n");
        bn_print("a: ", &a);
        bn_print("b: ", &b);
        printf("Result of comparison: %d\n", cmp_result);
    }
    printf("-- Finished testKernel for bn_cmp --\n");
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

#include <stdio.h>
#include <cuda_runtime.h>
#include "bignum.h"

// Test kernel for bn_divide
__global__ void test_div(BN_ULONG *A, BN_ULONG *B) {
    int success = 0;
    // Initialize 'dividend' and 'divisor' with test values for each test
    BIGNUM dividend, divisor, quotient, remainder;
    init_zero(&dividend, MAX_BIGNUM_WORDS);
    init_zero(&divisor, MAX_BIGNUM_WORDS);
    init_zero(&quotient, MAX_BIGNUM_WORDS);
    init_zero(&remainder, MAX_BIGNUM_WORDS);
    
    dividend.top = MAX_BIGNUM_WORDS;
    divisor.top = MAX_BIGNUM_WORDS;

    // Assign test values to 'dividend' and 'divisor', and initialize top accordingly
    for (int i = 0; i < MAX_BIGNUM_WORDS; ++i) {
        dividend.d[i] = A[i];
        divisor.d[i] = B[i];
    }
    bn_print("# dividend : ", &dividend);
    //printf("dividend top: %d\n", dividend.top);
    bn_print("# divisor  : ", &divisor);
    //printf("divisor top: %d\n", divisor.top);

    
    // Test division
    success = bn_div(&quotient, &remainder, &dividend, &divisor);

    // Print results
    if (success) {
        printf("Success\n");
    } else {
        printf("Failure\n");
    }
    bn_print("# quotient : ", &quotient);
    printf("quotient top: %d\n", quotient.top);
    bn_print("# remainder: ", &remainder);
    printf("remainder top: %d\n", remainder.top);
}

// Main function
int main() {
    /*BN_ULONG test_values_dividend[][MAX_BIGNUM_WORDS] = {
        {0,0,0,0xB}, // 0
        {0x1,0,0,0}, // 1
        {0,0,0x1234567890ABCDEF,0x7234567890ABCDEF}, // 2
        {0x1,0,0,0} // 3
    };

    BN_ULONG test_values_divisor[][MAX_BIGNUM_WORDS] = {
        {0,0,0,0x3}, // 0
        {0x2,0,0,0}, // 1
        {0,0,0x2,0}, // 2
        {0,0,0x100,0} // 3
    };*/
    BN_ULONG test_values_dividend[][MAX_BIGNUM_WORDS] = {
        {0,0,0,0xB}, // 0: Simple division
        {0x1,0,0,0}, // 1: Division by 1
        {0,0,0x1234567890ABCDEF,0x7234567890ABCDEF}, // 2: Large numbers
        {0x1,0,0,0}, // 3: Dividend smaller than divisor
        {0xFFFFFFFFFFFFFFFF,0xFFFFFFFFFFFFFFFF,0xFFFFFFFFFFFFFFFF,0xFFFFFFFFFFFFFFFF}, // 4: Maximum positive value
        {0x1,0,0,0x8000000000000000}, // 5: Negative dividend
        {0,0,0x1,0x8000000000000000}, // 6: Negative divisor
        {0x1,0,0,0x8000000000000000}, // 7: Both negative
        {0,0,0x1,0}, // 8: Multiple 16-sign words
        {0,0,0xFFFFFFFFFFFFFFFF,0}, // 9: Numerical order transition
        {0,0,0x1234567890ABCDEF,0x7234567890ABCDEF}, // 10: Large dividend, small divisor
        {0,0,0x1,0x7234567890ABCDEF}, // 11: Small dividend, large divisor
        {0,0,0,0}, // 12: Zero dividend
        {0x1234567890ABCDEF,0x7234567890ABCDEF,0x1234567890ABCDEF,0x7234567890ABCDEF}, // 13: Four-word dividend and divisor
        {0xFFFFFFFFFFFFFFFF,0,0,0}, // 14: Two-word dividend with maximum value in the first word
        {0,0xFFFFFFFFFFFFFFFF,0,0}, // 15: Two-word dividend with maximum value in the second word
    };

    BN_ULONG test_values_divisor[][MAX_BIGNUM_WORDS] = {
        {0,0,0,0x3}, // 0: Simple divisor
        {0x1,0,0,0}, // 1: Division by 1
        {0,0,0x2,0}, // 2: Large divisor
        {0,0,0x100,0}, // 3: Divisor larger than dividend
        {0x2,0,0,0}, // 4: Small divisor
        {0x2,0,0,0}, // 5: Positive divisor
        {0,0,0x1,0}, // 6: Negative divisor
        {0,0,0x1,0x8000000000000000}, // 7: Both negative
        {0,0,0x10,0}, // 8: Multiple 16-sign words in divisor
        {0,0,0x1,0}, // 9: Numerical order transition in divisor
        {0,0,0,0x1}, // 10: Small divisor
        {0,0,0x1234567890ABCDEF,0}, // 11: Large divisor
        {0,0,0,0x1}, // 12: Non-zero divisor for zero dividend
        {0x1234567890ABCDEF,0,0,0}, // 13: One-word divisor
        {0x100,0,0,0}, // 14: Divisor smaller than the first word of the dividend
        {0,0x100,0,0}, // 15: Divisor smaller than the second word of the dividend
    };

    int num_tests = sizeof(test_values_dividend) / sizeof(test_values_dividend[0]);

    printf("\n\n### CUDA test:\n");

    BN_ULONG *d_A, *d_B;
    cudaMalloc((void**)&d_A, MAX_BIGNUM_WORDS * sizeof(BN_ULONG));
    cudaMalloc((void**)&d_B, MAX_BIGNUM_WORDS * sizeof(BN_ULONG));

    for (int i = 0; i < num_tests; i++) {
        printf("\nTest %d:\n", i);

        cudaMemcpy(d_A, test_values_dividend[i], MAX_BIGNUM_WORDS * sizeof(BN_ULONG), cudaMemcpyHostToDevice);
        cudaMemcpy(d_B, test_values_divisor[i], MAX_BIGNUM_WORDS * sizeof(BN_ULONG), cudaMemcpyHostToDevice);

        // Launch the kernel to run the test
        test_div<<<1, 1>>>(d_A, d_B);

        // Check for any errors after running the kernel
        cudaError_t err = cudaGetLastError();
        if (err != cudaSuccess) {
            printf("Error: %s\n", cudaGetErrorString(err));
            //return -1;
        }

        // Wait for GPU to finish before accessing on host
        cudaDeviceSynchronize();
    }

    cudaFree(d_A);
    cudaFree(d_B);
    return 0;
}
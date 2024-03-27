//bn_div_test.cu
#include <stdio.h>
#include <cuda_runtime.h>
#include "bignum.h"

// Test kernel
__global__ void test(BN_ULONG *A, BN_ULONG *B) {
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
    bn_print("# divisor  : ", &divisor);

    // Test multiplication by divisor
    BIGNUM product;
    init_zero(&product, MAX_BIGNUM_WORDS);
    product.top = MAX_BIGNUM_WORDS;
    bn_mul(&dividend, &divisor, &product);
    bn_print("# &dividend, &divisor product  : ", &product);
    
    // Test division
    success = bn_div(&quotient, &remainder, &dividend, &divisor);

    // Print results
    if (success) {
        printf("Success\n");
    } else {
        printf("Failure\n");
    }
    bn_print("# quotient : ", &quotient);
    bn_print("# remainder: ", &remainder);

    // Test multiplication by divisor
    //BIGNUM product;
    init_zero(&product, MAX_BIGNUM_WORDS);
    product.top = MAX_BIGNUM_WORDS;
    bn_mul(&quotient, &divisor, &product);
    bn_print("\n Quotient * Divisor = ", &product);

    // Compare product with dividend
    if (bn_cmp(&product, &dividend) == 0) {
        printf("Product is equal to dividend\n");
    } else {
        printf("Product is not equal to dividend\n");
    }
    printf("\n");
}

// Main function
int main() {
    BN_ULONG test_values_dividend[][MAX_BIGNUM_WORDS] = {
        {0x80,0,0,0}, // Little endian
    };

    BN_ULONG test_values_divisor[][MAX_BIGNUM_WORDS] = {
        {0x4,0,0,0}, // Little endian
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
        test<<<1, 1>>>(d_A, d_B);

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
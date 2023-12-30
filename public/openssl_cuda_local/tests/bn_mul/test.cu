#include <stdio.h>
#include <cuda_runtime.h>
#include "bignum.h"

__global__ void test_bn_mul_kernel() {
    printf("++ test_bn_mul_kernel ++\n");

    /*Additional test cases:

    0x0000000000000000,0x0000000000000002 * 0x0000000000000000,0x0000000000000002
    0x0000000000000000,0x0000000000000002 * 0x0000000000000002,0x0000000000000000
    0x0000000000000002,0x0000000000000000 * 0x0000000000000000,0x0000000000000002
    0x0000000000000002,0x0000000000000000 * 0x0000000000000002,0x0000000000000000
    0x0000000000000001,0x0000000000000001 * 0x0000000000000001,0x0000000000000001
    0x0000000000000001,0x0000000000000000 * 0x0000000000000000,0x0000000000000001
    0x0000000000000001,0x0000000000000002 * 0x0000000000000003,0x0000000000000004
    0x0000000000000002,0x0000000000000001 * 0x0000000000000001,0x0000000000000003
    0xffffffffffffffff,0xffffffffffffffff * 0xffffffffffffffff,0xffffffffffffffff
    0xffffffffffffffff,0x0000000000000000 * 0x0000000000000000,0xffffffffffffffff
    0x00000000ffffffff,0x00000000ffffffff * 0xffffffff00000000,0xffffffff00000000
    0x0000000000000002,0x0000000000000000 * 0x0000000000000000,0x0000000000000001
    0x8000000000000000,0x0000000000000000 * 0x0000000000000002,0x0000000000000000
    0x8000000000000000,0x8000000000000000 * 0x0000000000000002,0x0000000000000002*/

    // Test cases similar to the ones used in the OpenSSL BN_mul test
    BN_ULONG test_values_a[] = {
        0x1ULL,
        0xFULL,
        0xFFULL,
        0xABCULL,
        0x1234567890ABCDEFULL,
        0x10ULL,
        0xFFFFFFFFFFFFFFFFULL/*,
        // Additional test cases
        0xFFFFFFFFFFFFFFFFULL,
        0x2ULL,
        0xFFFFFFFFFFFFFFFFULL,
        0x1ULL,
        0x0ULL,
        0xFFFFFFFFFFFFFFFFULL,
        0x8000000000000000ULL,
        0x8000000000000000ULL,
        0xFFFFFFFFFFFFFFFFULL,
        0x7FFFFFFFFFFFFFFFULL*/
    };

    BN_ULONG test_values_b[] = {
        0x2ULL,
        0xFULL,
        0x101ULL,
        0x10ULL,
        0xFEDCBA0987654321ULL,
        0x10ULL,
        0x1000000000000000ULL
        /*,// Additional test cases corresponding to the extended test values in 'a'
        0x2ULL,
        0xFFFFFFFFFFFFFFFFULL,
        0x1ULL,
        0xFFFFFFFFFFFFFFFFULL,
        0x0ULL,
        0x8000000000000000ULL,
        0x2ULL,
        0x8000000000000000ULL,
        0xFFFFFFFFFFFFFFFFULL,
        0x2ULL*/
    };

    int num_tests = sizeof(test_values_a) / sizeof(test_values_a[0]);

    for (int test = 0; test < num_tests; ++test) {
        printf("Test %d:\n", test + 1);
        // Initialize BIGNUMs for testing
        BIGNUM a, b, product;
        init_zero(&a, MAX_BIGNUM_WORDS);
        init_zero(&b, MAX_BIGNUM_WORDS);
        init_zero(&product, MAX_BIGNUM_WORDS);

        // Initialize 'a' and 'b' with the test values
        a.d[0] = test_values_a[test]; a.top = 1;
        b.d[0] = test_values_b[test]; b.top = 1;

        // Test bn_mul operation
        bn_mul(&a, &b, &product);

        // Print result
        
        bn_print("a: ", &a);
        bn_print("b: ", &b);
        bn_print("a * b = product: ", &product);
        // Print product top
        printf("product.top = %d\n", product.top);
    }

    printf("-- Finished test_bn_mul_kernel --\n");
}

// Main function
int main() {
    printf("Starting bn_mul test\n");
    // Launch the kernel to run the test
    test_bn_mul_kernel<<<1, 1>>>();

    // Wait for GPU to finish before accessing on host
    cudaDeviceSynchronize();

    // Check for any errors after running the kernel
    cudaError_t err = cudaGetLastError();
    if (err != cudaSuccess) {
        printf("Error after running kernel: %s\n", cudaGetErrorString(err));
        return -1;
    }

    return 0;
}

// Compile this program with:
// nvcc test_bn_mul.cu -o test_bn_mul -I<path_to_bignum_header>
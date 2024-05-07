#include <stdio.h>
#include <cuda_runtime.h>
#include "bignum.h"
#include <cuda_profiler_api.h>

#define TEST_BIGNUM_WORDS 9

__device__ void reverse_order(BN_ULONG test_values_a[][TEST_BIGNUM_WORDS], BN_ULONG test_values_b[][TEST_BIGNUM_WORDS], size_t num_rows) {
    for (size_t i = 0; i < num_rows; i++) {
        for (size_t j = 0; j < TEST_BIGNUM_WORDS / 2; j++) {
            BN_ULONG temp_a = test_values_a[i][j];
            test_values_a[i][j] = test_values_a[i][TEST_BIGNUM_WORDS - 1 - j];
            test_values_a[i][TEST_BIGNUM_WORDS - 1 - j] = temp_a;

            BN_ULONG temp_b = test_values_b[i][j];
            test_values_b[i][j] = test_values_b[i][TEST_BIGNUM_WORDS - 1 - j];
            test_values_b[i][TEST_BIGNUM_WORDS - 1 - j] = temp_b;
        }
    }
}

__global__ void testKernel() {
    printf("++ testKernel for bn_mod_inverse ++\n");
    BN_ULONG test_values_a[][MAX_BIGNUM_WORDS] = {
        // {0,0,0,0,0,0x35c2d1fd4c7b8673, 0x478b08328cd9d5dd, 0xefec64ca64cda1c2, 0x46c86352a19fca54},
        {0,0,0,0,0,0x76e64113f677cf0e, 0x10a2570d599968d3, 0x1544e179b7604329, 0x52c02a4417bdde39}, // Before ### Step: 100
    };

    BN_ULONG test_values_n[][MAX_BIGNUM_WORDS] = {
        // {0,0,0,0,0,0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xfffffffefffffc2f},
        {0,0,0,0,0,0xc90ddf8dee4e95cf, 0x577066d70681f0d3, 0x5e2a33d2b56d2032, 0xb4b1752d1901ac01},
    };

    // 0 for positive, 1 for negative
    int sign_a[] = {0};
    int sign_n[] = {0};
    
    reverse_order(test_values_a, test_values_n, sizeof(test_values_a) / (sizeof(BN_ULONG) * TEST_BIGNUM_WORDS));
    
    int num_tests = sizeof(test_values_a) / (sizeof(BN_ULONG) * TEST_BIGNUM_WORDS);
    // int limit = 20;
    bool mod_inverse_exists;
    for (int test = 0; test < num_tests; ++test) {
        BIGNUM value_a, value_n, result;
        init_zero(&value_a, MAX_BIGNUM_SIZE);
        init_zero(&value_n, MAX_BIGNUM_SIZE);
        init_zero(&result, MAX_BIGNUM_SIZE);

        // Initialize 'value_a' and 'value_n' with the test values
        for (int j = 0; j < TEST_BIGNUM_WORDS; ++j) {
            value_a.d[j] = test_values_a[test][j];
            value_n.d[j] = test_values_n[test][j];
        }
        value_a.top = find_top(&value_a, MAX_BIGNUM_SIZE);
        value_n.top = find_top(&value_n, MAX_BIGNUM_SIZE);

        //value_a.neg = sign_a[test];
        //value_n.neg = sign_b[test];

        printf("\n]================>> Test %d:\n", test);
        bn_print("a: ", &value_a);
        bn_print("n: ", &value_n);

        // Test the bn_mod_inverse function
        mod_inverse_exists = bn_mod_inverse(&result, &value_a, &value_n);
        // Print the result
        printf("[%d] ", test);
        if (mod_inverse_exists) bn_print("Modular inverse: ", &result);
        else printf("No modular inverse exists for the given 'a' and 'n'.\n");
        printf("\n");
        // limit -= 1;
        // if (limit == 0) {
        //     break;
        // }
    }
    printf("\nTimers:\n");
    printf("elapsed_time_bn_copy: %.6f\n", elapsed_time_bn_copy);
    printf("elapsed_time_bn_div: %.6f\n", elapsed_time_bn_div);
    printf("elapsed_time_bn_div_binary: %.6f\n", elapsed_time_bn_div_binary);
    printf("elapsed_time_bn_mod_inverse: %.6f\n", elapsed_time_bn_mod_inverse);
    printf("\nCounters:\n");
    printf("bn_div: %d\n", debug_loop_counter_bn_div);
}

// Main function
int main() {
    // cudaDeviceSetSharedMemConfig(cudaSharedMemBankSizeEightByte);
    // Set the shared memory bank size to eight bytes
    // cudaError_t err = cudaDeviceSetSharedMemConfig(cudaSharedMemBankSizeEightByte);
    // if (err != cudaSuccess) {
    //     printf("Failed to set shared memory configuration: %s\n", cudaGetErrorString(err));
    //     return 1;
    // }
    // Set the shared memory bank size to eight bytes for the kernel function
    cudaError_t err = cudaFuncSetAttribute(&testKernel, cudaFuncAttributeMaxDynamicSharedMemorySize, cudaSharedMemBankSizeEightByte);
    if (err != cudaSuccess) {
        printf("Failed to set shared memory configuration: %s\n", cudaGetErrorString(err));
        return 1;
    }
    // Start the profiling range
    cudaProfilerStart();
    testKernel<<<1, 1>>>();
    err = cudaGetLastError();
    if (err != cudaSuccess) {
        printf("Error: %s\n", cudaGetErrorString(err));
        return -1;
    }
    cudaDeviceSynchronize();
    // Stop the profiling range
    cudaProfilerStop();
    return 0;
}
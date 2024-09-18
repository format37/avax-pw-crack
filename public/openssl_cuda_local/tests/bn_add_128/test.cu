#include <stdio.h>
#include <cuda_runtime.h>
#include "bignum.h"
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <string.h>

#define BN_ULONG_HOST unsigned long long // __int128 transferring to CUDA is not supported
#ifdef BN_128
    #define MAX_BIGNUM_SIZE_HOST MAX_BIGNUM_SIZE * 2
#else
    #define MAX_BIGNUM_SIZE_HOST MAX_BIGNUM_SIZE
#endif

__global__ void kernel_test(BN_ULONG_HOST *A, BN_ULONG_HOST *B, int *sign_a, int *sign_b, BN_ULONG_HOST *Result, int *Result_sign) {
    // Initialize values for each test
    BIGNUM a, b, result;
    init_zero(&a);
    init_zero(&b);
    init_zero(&result);
    // Set the sign of the numbers
    a.neg = sign_a[0];
    b.neg = sign_b[0];

    // printf("\n");
    // for (int i = 0; i < MAX_BIGNUM_SIZE_HOST; ++i) {
    //     printf("A[%d]: %llx\n", i, A[i]);
    // }
    // printf("\n");
    // for (int i = 0; i < MAX_BIGNUM_SIZE_HOST; ++i) {
    //     printf("B[%d]: %llx\n", i, B[i]);
    // }
    // printf("\n");
    #ifdef BN_128
        for (int i = 0; i < MAX_BIGNUM_SIZE_HOST; i += 2) {
            a.d[i/2] = ((__int128)A[i+1] << 64) | A[i];
            b.d[i/2] = ((__int128)B[i+1] << 64) | B[i];
        }
    #else
        for (int i = 0; i < MAX_BIGNUM_SIZE_HOST; ++i) {
            a.d[i] = A[i];
            b.d[i] = B[i];
        }
    #endif

    a.top = find_top(&a);
    b.top = find_top(&b);

    // bn_print("# a : ", &a);
    // bn_print("# b : ", &b);

    // Test
    bn_add(&result, &a, &b);

    // Print results
    // bn_print("# result: ", &result);

    // Copy result back to host
    #ifdef BN_128
        for (int i = 0; i < MAX_BIGNUM_SIZE_HOST; i += 2) {
            Result[i] = (BN_ULONG_HOST)(result.d[i/2] & 0xFFFFFFFFFFFFFFFFULL);
            Result[i+1] = (BN_ULONG_HOST)(result.d[i/2] >> 64);
        }
    #else
        for (int i = 0; i < MAX_BIGNUM_SIZE_HOST; ++i) {
            Result[i] = result.d[i];
        }
    #endif
    *Result_sign = result.neg;
    result.top = find_top(&result);
}

void print_bn(const char* label, const BIGNUM* bn) {
    char *str = BN_bn2hex(bn);
    printf("%s: %s\n", label, str);
    OPENSSL_free(str);
}

int compare_results(BN_ULONG_HOST* cuda_result, int cuda_sign, BIGNUM* openssl_result, int top) {
    BIGNUM* cuda_bn = BN_new();
    BN_zero(cuda_bn);

    for (int i = top - 1; i >= 0; --i) {
        BN_lshift(cuda_bn, cuda_bn, 64);
        BN_add_word(cuda_bn, cuda_result[i]);
    }

    if (cuda_sign) {
        BN_set_negative(cuda_bn, 1);
    }

    int comparison = BN_cmp(cuda_bn, openssl_result);
    BN_free(cuda_bn);

    return comparison == 0;
}

// Main function
int main() {
    BN_ULONG_HOST test_values_a[][MAX_BIGNUM_SIZE_HOST] = {
        {0xa, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0, 0, 0, 0, 0},
        {0xffffffffffffffff, 0xffffffffffffffff, 0, 0, 0, 0, 0, 0, 0, 0},
        {0, 0, 0, 0x1, 0, 0, 0, 0, 0, 0}, // 2
        {0xffffffffffffffff, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        {0xffffffffffffffff, 0xffffffffffffffff, 0, 0, 0, 0, 0, 0, 0, 0},
        {0x1234567890abcdef, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        {0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0, 0, 0, 0, 0, 0},
        {0x1234567890abcdef, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        {0x1234567890abcdef, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        {0x1234567890abcdef, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        {0x1234567890abcdef, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        {0x405000A0CA2248E1, 0xB788A1C84F4C756C, 0xAB7087E3F0C50175, 0xC17747B1566D9FE8, 0, 0, 0, 0, 0, 0},
    };

    BN_ULONG_HOST test_values_b[][MAX_BIGNUM_SIZE_HOST] = {
        {0x1, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        {0x1, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0x2}, // 2
        {0x1, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        {0x1, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        {0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0, 0, 0, 0, 0, 0},
        {0x5678901234567890, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        {0x5678901234567890, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        {0xfedcba0987654321, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        {0xfedcba0987654321, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        {0x158A7E6564F93CDF, 0xD204BB99DD677993, 0xA7596D16B56D2AEF, 0x6C91CEA9CF0CAC55, 0, 0, 0, 0, 0, 0},
    };

    // Set sign to 0 for positive numbers, 1 for negative numbers
    int sign_a[] = {0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0};
    int sign_b[] = {0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0};

    int num_tests = sizeof(test_values_a) / sizeof(test_values_a[0]);

    printf("\n\n### CUDA test:\n");

    BN_ULONG_HOST *d_A, *d_B, *d_Result;
    int *d_sign_a, *d_sign_b, *d_Result_sign;
    cudaMalloc((void**)&d_A, MAX_BIGNUM_SIZE_HOST * sizeof(BN_ULONG_HOST));
    cudaMalloc((void**)&d_B, MAX_BIGNUM_SIZE_HOST * sizeof(BN_ULONG_HOST));
    cudaMalloc((void**)&d_Result, MAX_BIGNUM_SIZE_HOST * sizeof(BN_ULONG_HOST));
    cudaMalloc((void**)&d_sign_a, sizeof(int));
    cudaMalloc((void**)&d_sign_b, sizeof(int));
    cudaMalloc((void**)&d_Result_sign, sizeof(int));

    // OpenSSL context
    BN_CTX *ctx = BN_CTX_new();
    OPENSSL_assert(ctx != NULL);

    for (int i = 0; i < num_tests; i++) {
        printf("\nTest %d:\n", i);

        // CUDA part
        cudaMemcpy(d_A, test_values_a[i], MAX_BIGNUM_SIZE_HOST * sizeof(BN_ULONG_HOST), cudaMemcpyHostToDevice);
        cudaMemcpy(d_B, test_values_b[i], MAX_BIGNUM_SIZE_HOST * sizeof(BN_ULONG_HOST), cudaMemcpyHostToDevice);
        cudaMemcpy(d_sign_a, &sign_a[i], sizeof(int), cudaMemcpyHostToDevice);
        cudaMemcpy(d_sign_b, &sign_b[i], sizeof(int), cudaMemcpyHostToDevice);

        // Launch the kernel to run the test
        kernel_test<<<1, 1>>>(d_A, d_B, d_sign_a, d_sign_b, d_Result, d_Result_sign);

        // Check for any errors after running the kernel
        cudaError_t err = cudaGetLastError();
        if (err != cudaSuccess) {
            printf("Error: %s\n", cudaGetErrorString(err));
        }

        // Wait for GPU to finish before accessing on host
        cudaDeviceSynchronize();

        // Copy CUDA result back to host
        BN_ULONG_HOST cuda_result[MAX_BIGNUM_SIZE_HOST];
        int cuda_result_sign;
        cudaMemcpy(cuda_result, d_Result, MAX_BIGNUM_SIZE_HOST * sizeof(BN_ULONG_HOST), cudaMemcpyDeviceToHost);
        cudaMemcpy(&cuda_result_sign, d_Result_sign, sizeof(int), cudaMemcpyDeviceToHost);

        // OpenSSL part
        BIGNUM *a = BN_new();
        BIGNUM *b = BN_new();
        BIGNUM *result = BN_new();

        BN_set_word(a, test_values_a[i][MAX_BIGNUM_SIZE_HOST - 1]);
        BN_set_word(b, test_values_b[i][MAX_BIGNUM_SIZE_HOST - 1]);

        for (int j = MAX_BIGNUM_SIZE_HOST - 2; j >= 0; --j) {
            BN_lshift(a, a, 64);
            BN_lshift(b, b, 64);
            BN_add_word(a, test_values_a[i][j]);
            BN_add_word(b, test_values_b[i][j]);
        }

        // Set the sign of the numbers
        BN_set_negative(a, sign_a[i]);
        BN_set_negative(b, sign_b[i]);

        // Test addition (a + b)
        if(!BN_add(result, a, b)) {
            fprintf(stderr, "Addition failed for test case %d\n", i + 1);
        }

        // printf("\nOpenSSL results:\n");
        // print_bn("a", a);
        // print_bn("b", b);
        // print_bn("result", result);

        // Compare CUDA and OpenSSL results
        if (compare_results(cuda_result, cuda_result_sign, result, MAX_BIGNUM_SIZE_HOST)) {
            printf("Test PASSED: CUDA and OpenSSL results match.\n");
        } else {
            printf("### Test FAILED: CUDA and OpenSSL results DO NOT MATCH. ###\n");
            printf("CUDA result sign: %d\n", cuda_result_sign);
        }

        BN_free(a);
        BN_free(b);
        BN_free(result);
        // break; // Break after the first test. TODO: Remove this line
    }

    cudaFree(d_A);
    cudaFree(d_B);
    cudaFree(d_Result);
    cudaFree(d_sign_a);
    cudaFree(d_sign_b);
    cudaFree(d_Result_sign);
    BN_CTX_free(ctx);
    return 0;
}
#include <stdio.h>
#include <cuda_runtime.h>
#include "bignum.h"
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <string.h>

#define MAX_BIGNUM_WORDS 4     // For 256-bit numbers

__global__ void kernel_test(BN_ULONG *A, BN_ULONG *B, int *sign_a, int *sign_b, BN_ULONG *Result, int *Result_sign) {
    // Initialize values for each test
    BIGNUM a, b, result;
    init_zero(&a);
    init_zero(&b);
    init_zero(&result);

    a.top = MAX_BIGNUM_SIZE;
    b.top = MAX_BIGNUM_SIZE;
    result.top = MAX_BIGNUM_SIZE;

    // Assign test values and initialize top accordingly
    for (int i = 0; i < MAX_BIGNUM_SIZE; ++i) {
        a.d[i] = A[i];
        b.d[i] = B[i];
    }

    // Set the sign of the numbers
    a.neg = sign_a[0];
    b.neg = sign_b[0];

    bn_print("# a : ", &a);
    bn_print("# b : ", &b);

    // Test
    bn_add(&result, &a, &b);

    // Print results
    bn_print("# result: ", &result);
    printf("top: %d\n", result.top);

    // Copy result back to host
    for (int i = 0; i < MAX_BIGNUM_SIZE; ++i) {
        Result[i] = result.d[i];
    }
    *Result_sign = result.neg;
}

void print_bn(const char* label, const BIGNUM* bn) {
    char *str = BN_bn2hex(bn);
    // printf("%s: %s%s\n", label, BN_is_negative(bn) ? "-" : "", str);
    printf("%s: %s\n", label, str);
    OPENSSL_free(str);
}

int compare_results(BN_ULONG* cuda_result, int cuda_sign, BIGNUM* openssl_result, int top) {
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
    BN_ULONG test_values_a[][MAX_BIGNUM_SIZE] = {
        {2},
        {0xffffffffffffffff, 0xffffffffffffffff, 0,0}, // 0
        {0,0,0,0x1}, // 1
        {0xffffffffffffffff, 0,0,0}, // 2
        {0xffffffffffffffff, 0xffffffffffffffff, 0,0}, // 3
        {0x1234567890abcdef, 0,0,0}, // 4
        {0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff}, // 5
        {0x1234567890abcdef, 0,0,0}, // 6
        {0x1234567890abcdef, 0,0,0}, // 7
        {0x1234567890abcdef, 0,0,0}, // 8
        {0x1234567890abcdef, 0,0,0},  // 9
        {0x405000A0CA2248E1, 0xB788A1C84F4C756C, 0xAB7087E3F0C50175, 0xC17747B1566D9FE8}, //10
    };

    BN_ULONG test_values_b[][MAX_BIGNUM_SIZE] = {
        {3},
        {0x1, 0,0,0}, // 0
        {0,0,0,0x2}, // 1
        {0x1, 0,0,0}, // 2
        {0x1, 0,0,0}, // 3
        {0,0,0,0}, // 4
        {0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff}, // 5
        {0x5678901234567890, 0,0,0}, // 6
        {0x5678901234567890, 0,0,0}, // 7
        {0xfedcba0987654321, 0,0,0}, // 8
        {0xfedcba0987654321, 0,0,0},  // 9
        {0x158A7E6564F93CDF, 0xD204BB99DD677993, 0xA7596D16B56D2AEF, 0x6C91CEA9CF0CAC55},  // 10
    };

    // Set sign to 0 for positive numbers, 1 for negative numbers
    int sign_a[] = {0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0};
    int sign_b[] = {0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0};

    int num_tests = sizeof(test_values_a) / sizeof(test_values_a[0]);

    printf("\n\n### CUDA test:\n");

    BN_ULONG *d_A, *d_B, *d_Result;
    int *d_sign_a, *d_sign_b, *d_Result_sign;
    cudaMalloc((void**)&d_A, MAX_BIGNUM_SIZE * sizeof(BN_ULONG));
    cudaMalloc((void**)&d_B, MAX_BIGNUM_SIZE * sizeof(BN_ULONG));
    cudaMalloc((void**)&d_Result, MAX_BIGNUM_SIZE * sizeof(BN_ULONG));
    cudaMalloc((void**)&d_sign_a, sizeof(int));
    cudaMalloc((void**)&d_sign_b, sizeof(int));
    cudaMalloc((void**)&d_Result_sign, sizeof(int));

    // OpenSSL context
    BN_CTX *ctx = BN_CTX_new();
    OPENSSL_assert(ctx != NULL);

    for (int i = 0; i < num_tests; i++) {
        printf("\nTest %d:\n", i);

        // CUDA part
        cudaMemcpy(d_A, test_values_a[i], MAX_BIGNUM_SIZE * sizeof(BN_ULONG), cudaMemcpyHostToDevice);
        cudaMemcpy(d_B, test_values_b[i], MAX_BIGNUM_SIZE * sizeof(BN_ULONG), cudaMemcpyHostToDevice);
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
        BN_ULONG cuda_result[MAX_BIGNUM_SIZE];
        int cuda_result_sign;
        cudaMemcpy(cuda_result, d_Result, MAX_BIGNUM_SIZE * sizeof(BN_ULONG), cudaMemcpyDeviceToHost);
        cudaMemcpy(&cuda_result_sign, d_Result_sign, sizeof(int), cudaMemcpyDeviceToHost);

        // OpenSSL part
        BIGNUM *a = BN_new();
        BIGNUM *b = BN_new();
        BIGNUM *result = BN_new();

        BN_set_word(a, test_values_a[i][MAX_BIGNUM_WORDS - 1]);
        BN_set_word(b, test_values_b[i][MAX_BIGNUM_WORDS - 1]);

        for (int j = MAX_BIGNUM_WORDS - 2; j >= 0; --j) {
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

        printf("\nOpenSSL results:\n");
        print_bn("a", a);
        print_bn("b", b);
        print_bn("result", result);

        // Compare CUDA and OpenSSL results
        if (compare_results(cuda_result, cuda_result_sign, result, MAX_BIGNUM_SIZE)) {
            printf("Test passed: CUDA and OpenSSL results match.\n");
        } else {
            printf("### Test failed: CUDA and OpenSSL results DO NOT MATCH. ###\n");
            printf("CUDA result sign: %d\n", cuda_result_sign);
        }

        BN_free(a);
        BN_free(b);
        BN_free(result);
        break;
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
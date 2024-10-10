#include <cuda_runtime.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <stdio.h>
#include "bignum.h"

#define NUM_TESTS 5
#define BN_ULONG_HOST unsigned long long

__global__ void kernel_test_mod_sqr(BN_ULONG_HOST *R, int *R_sign) {
    BIGNUM_CUDA test_values_a[NUM_TESTS];
    BIGNUM_CUDA test_values_m[NUM_TESTS];
    BIGNUM_CUDA result;

    // Initialize test values
    for (int i = 0; i < NUM_TESTS; i++) {
        init_zero(&test_values_a[i]);
        init_zero(&test_values_m[i]);
    }

    // Test case 1
    test_values_a[0].neg = false; test_values_a[0].top = 1; test_values_a[0].d[0] = 0xA;
    test_values_m[0].neg = false; test_values_m[0].top = 1; test_values_m[0].d[0] = 7;

    // Test case 2
    test_values_a[1].neg = false; test_values_a[1].top = 2;
    test_values_a[1].d[0] = 0xA54B1234CDEF5678ULL; test_values_a[1].d[1] = 0x1234567890ABCDEFULL;
    test_values_m[1].neg = false; test_values_m[1].top = 1;
    test_values_m[1].d[0] = 0xFFFFFFFFFFFFFFFDULL; test_values_m[1].d[1] = 0;

    // Test case 3
    test_values_a[2].neg = true; test_values_a[2].top = 1; test_values_a[2].d[0] = 50;
    test_values_m[2].neg = false; test_values_m[2].top = 1; test_values_m[2].d[0] = 13;

    // Test case 4
    test_values_a[3].neg = false; test_values_a[3].top = 1; test_values_a[3].d[0] = 12345;
    test_values_m[3].neg = false; test_values_m[3].top = 1; test_values_m[3].d[0] = 987654321;

    // Test case 5
    test_values_a[4].neg = false; test_values_a[4].top = 2;
    test_values_a[4].d[0] = 0xFFFFFFFFFFFFFFFFULL; test_values_a[4].d[1] = 0xFFFFFFFFFFFFFFFFULL;
    test_values_m[4].neg = false; test_values_m[4].top = 2;
    test_values_m[4].d[0] = 0xFFFFFFFFFFFFFFFFULL; test_values_m[4].d[1] = 0xFFFFFFFFFFFFFFFBULL;

    for (int i = 0; i < NUM_TESTS; i++) {
        init_zero(&result);
        int ret = bn_mod_sqr(&result, &test_values_a[i], &test_values_m[i]);
        
        if (ret != 1) {
            printf("bn_mod_sqr failed for test case %d\n", i);
            continue;
        }

        for (int j = 0; j < MAX_BIGNUM_SIZE; j++) {
            R[i * MAX_BIGNUM_SIZE + j] = result.d[j];
        }
        R_sign[i] = result.neg;
    }
}

int main() {
    BN_ULONG_HOST *d_R;
    int *d_R_sign;
    cudaError_t err;

    err = cudaMalloc((void**)&d_R, NUM_TESTS * MAX_BIGNUM_SIZE * sizeof(BN_ULONG_HOST));
    if (err != cudaSuccess) {printf("cudaMalloc failed for d_R: %s\n", cudaGetErrorString(err)); return -1;}
    err = cudaMalloc((void**)&d_R_sign, NUM_TESTS * sizeof(int));
    if (err != cudaSuccess) {printf("cudaMalloc failed for d_R_sign: %s\n", cudaGetErrorString(err)); return -1;}

    kernel_test_mod_sqr<<<1, 1>>>(d_R, d_R_sign);

    cudaError_t kernel_err = cudaGetLastError();
    if (kernel_err != cudaSuccess) {
        printf("Kernel execution error: %s\n", cudaGetErrorString(kernel_err));
        return -1;
    }

    cudaDeviceSynchronize();

    BN_ULONG_HOST cuda_R[NUM_TESTS][MAX_BIGNUM_SIZE];
    int cuda_R_sign[NUM_TESTS];
    cudaMemcpy(cuda_R, d_R, NUM_TESTS * MAX_BIGNUM_SIZE * sizeof(BN_ULONG_HOST), cudaMemcpyDeviceToHost);
    cudaMemcpy(cuda_R_sign, d_R_sign, NUM_TESTS * sizeof(int), cudaMemcpyDeviceToHost);

    BN_CTX *ctx = BN_CTX_new();
    OPENSSL_assert(ctx != NULL);

    // OpenSSL test values
    BN_ULONG_HOST test_values_a[][2] = {
        {10, 0},
        {0x1234567890ABCDEFULL, 0xA54B1234CDEF5678ULL},
        {50, 0},
        {12345, 0},
        {0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL}
    };

    BN_ULONG_HOST test_values_m[][2] = {
        {7, 0},
        {0xFFFFFFFFFFFFFFFDULL, 0},
        {13, 0},
        {987654321, 0},
        {0xFFFFFFFFFFFFFFFBULL, 0xFFFFFFFFFFFFFFFFULL}
    };

    int sign_a[] = {0, 0, 1, 0, 0};

    for (int i = 0; i < NUM_TESTS; i++) {
        printf("\nTest %d:\n", i + 1);

        BIGNUM *a = BN_new();
        BIGNUM *m = BN_new();
        BIGNUM *r = BN_new();
        BIGNUM *cuda_result = BN_new();

        BN_set_word(a, test_values_a[i][0]);
        if (test_values_a[i][1] > 0) {
            BN_lshift(a, a, 64);
            BN_add_word(a, test_values_a[i][1]);
        }
        BN_set_negative(a, sign_a[i]);

        BN_set_word(m, test_values_m[i][0]);
        if (test_values_m[i][1] > 0) {
            BN_lshift(m, m, 64);
            BN_add_word(m, test_values_m[i][1]);
        }

        if(!BN_mod_sqr(r, a, m, ctx)) {
            fprintf(stderr, "BN_mod_sqr failed for test case %d\n", i + 1);
            continue;
        }

        BN_zero(cuda_result);
        for (int j = MAX_BIGNUM_SIZE - 1; j >= 0; --j) {
            BN_lshift(cuda_result, cuda_result, 64);
            BN_add_word(cuda_result, cuda_R[i][j]);
        }
        BN_set_negative(cuda_result, cuda_R_sign[i]);

        if (BN_cmp(cuda_result, r) == 0) {
            printf("Test PASSED: CUDA and OpenSSL results match.\n");
        } else {
            printf("Test FAILED: CUDA and OpenSSL results DO NOT MATCH.\n");
            char *cuda_str = BN_bn2hex(cuda_result);
            char *openssl_str = BN_bn2hex(r);
            // Print openssl input test values
            printf(">> a: %s\n", BN_bn2hex(a));
            printf(">> m: %s\n", BN_bn2hex(m));
            printf("CUDA result:    %s\n", cuda_str);
            printf("OpenSSL result: %s\n", openssl_str);
            OPENSSL_free(cuda_str);
            OPENSSL_free(openssl_str);
        }

        BN_free(a);
        BN_free(m);
        BN_free(r);
        BN_free(cuda_result);
    }

    cudaFree(d_R);
    cudaFree(d_R_sign);
    BN_CTX_free(ctx);

    return 0;
}
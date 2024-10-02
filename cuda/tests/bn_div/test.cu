// bn_div_test.cu
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

__global__ void kernel_test_div(
    BN_ULONG_HOST *A, 
    BN_ULONG_HOST *B, 
    int *sign_a, 
    int *sign_b, 
    BN_ULONG_HOST *Q, 
    int *Q_sign, 
    BN_ULONG_HOST *R, 
    int *R_sign,
    ThreadFunctionProfile *d_threadFunctionProfiles_param
    ) {
    #ifdef function_profiler
        unsigned long long start_time = clock64();
        // Set the device global variable
        d_threadFunctionProfiles = d_threadFunctionProfiles_param;
    #endif
    // Initialize values for each test
    BIGNUM a, b, quotient, remainder;
    init_zero(&a);
    init_zero(&b);
    init_zero(&quotient);
    init_zero(&remainder);

    // Set the sign of the numbers
    a.neg = sign_a[0];
    b.neg = sign_b[0];

    // Load the data into a and b
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

    // Call bn_div
    int ret = bn_div(&quotient, &remainder, &a, &b);
    if (ret != 1) {
        printf("bn_div failed\n");
        return;
    }

    // Copy quotient and remainder back to host
    #ifdef BN_128
        for (int i = 0; i < MAX_BIGNUM_SIZE_HOST; i += 2) {
            Q[i] = (BN_ULONG_HOST)(quotient.d[i/2] & 0xFFFFFFFFFFFFFFFFULL);
            Q[i+1] = (BN_ULONG_HOST)(quotient.d[i/2] >> 64);
            R[i] = (BN_ULONG_HOST)(remainder.d[i/2] & 0xFFFFFFFFFFFFFFFFULL);
            R[i+1] = (BN_ULONG_HOST)(remainder.d[i/2] >> 64);
        }
    #else
        for (int i = 0; i < MAX_BIGNUM_SIZE_HOST; ++i) {
            Q[i] = quotient.d[i];
            R[i] = remainder.d[i];
        }
    #endif
    *Q_sign = quotient.neg;
    *R_sign = remainder.neg;
    #ifdef function_profiler
        record_function(FN_MAIN, start_time);
    #endif
}

void print_bn(const char* label, const BIGNUM* bn) {
    char *str = BN_bn2hex(bn);
    printf("%s: %s\n", label, str);
    OPENSSL_free(str);
}

int compare_bn_results(BN_ULONG_HOST* cuda_result, int cuda_sign, BIGNUM* openssl_result, int top) {
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

int main() {
    #ifdef BN_128
        printf("\nBN_128\n");
    #else
        printf("\nBN_64\n");
    #endif

    // Prepare test data
    BN_ULONG_HOST test_values_a[][MAX_BIGNUM_SIZE_HOST] = {
        {10, 0, 0, 0, 0, 0, 0, 0, 0, 0}, // Test 0
        {100, 0, 0, 0, 0, 0, 0, 0, 0, 0}, // Test 1
        {0xA54B1234CDEF5678ULL, 0x1234567890ABCDEFULL, 0, 0, 0, 0, 0, 0, 0, 0}, // Test 2
        {50, 0, 0, 0, 0, 0, 0, 0, 0, 0}, // Test 3 (negative a)
        {50, 0, 0, 0, 0, 0, 0, 0, 0, 0}, // Test 4
        {50, 0, 0, 0, 0, 0, 0, 0, 0, 0}, // Test 5 (negative a)
        {12345, 0, 0, 0, 0, 0, 0, 0, 0, 0}, // Test 6 (small a)
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, // Test 7 (a = 0)
    };

    BN_ULONG_HOST test_values_b[][MAX_BIGNUM_SIZE_HOST] = {
        {2, 0, 0, 0, 0, 0, 0, 0, 0, 0}, // Test 0
        {3, 0, 0, 0, 0, 0, 0, 0, 0, 0}, // Test 1
        {987654321, 0, 0, 0, 0, 0, 0, 0, 0, 0}, // Test 2
        {7, 0, 0, 0, 0, 0, 0, 0, 0, 0}, // Test 3
        {7, 0, 0, 0, 0, 0, 0, 0, 0, 0}, // Test 4 (negative b)
        {7, 0, 0, 0, 0, 0, 0, 0, 0, 0}, // Test 5 (negative b)
        {12345678901234567890ULL, 0, 0, 0, 0, 0, 0, 0, 0, 0}, // Test 6 (large b)
        {12345, 0, 0, 0, 0, 0, 0, 0, 0, 0}, // Test 7
    };

    int sign_a[] = {0, 0, 0, 1, 0, 1, 0, 0};
    int sign_b[] = {0, 0, 0, 0, 1, 1, 0, 0};

    int num_tests = sizeof(test_values_a) / sizeof(test_values_a[0]);

    printf("\n\n### CUDA division test:\n");

    BN_ULONG_HOST *d_A, *d_B, *d_Q, *d_R;
    int *d_sign_a, *d_sign_b, *d_Q_sign, *d_R_sign;
    cudaMalloc((void**)&d_A, MAX_BIGNUM_SIZE_HOST * sizeof(BN_ULONG_HOST));
    cudaMalloc((void**)&d_B, MAX_BIGNUM_SIZE_HOST * sizeof(BN_ULONG_HOST));
    cudaMalloc((void**)&d_Q, MAX_BIGNUM_SIZE_HOST * sizeof(BN_ULONG_HOST));
    cudaMalloc((void**)&d_R, MAX_BIGNUM_SIZE_HOST * sizeof(BN_ULONG_HOST));
    cudaMalloc((void**)&d_sign_a, sizeof(int));
    cudaMalloc((void**)&d_sign_b, sizeof(int));
    cudaMalloc((void**)&d_Q_sign, sizeof(int));
    cudaMalloc((void**)&d_R_sign, sizeof(int));

    // Function profiling
    int threadsPerBlock = 1;
    int blocksPerGrid = 1;
    int totalThreads = blocksPerGrid * threadsPerBlock;
    // Allocate per-thread function profiling data
    ThreadFunctionProfile *h_threadFunctionProfiles = new ThreadFunctionProfile[totalThreads];
    ThreadFunctionProfile *d_threadFunctionProfiles;
    cudaMalloc(&d_threadFunctionProfiles, totalThreads * sizeof(ThreadFunctionProfile));
    cudaMemset(d_threadFunctionProfiles, 0, totalThreads * sizeof(ThreadFunctionProfile));

    BN_CTX *ctx = BN_CTX_new();
    OPENSSL_assert(ctx != NULL);

    for (int i = 0; i < num_tests; i++) {
        printf("\nTest %d:\n", i);

        // Copy test data to device
        cudaMemcpy(d_A, test_values_a[i], MAX_BIGNUM_SIZE_HOST * sizeof(BN_ULONG_HOST), cudaMemcpyHostToDevice);
        cudaMemcpy(d_B, test_values_b[i], MAX_BIGNUM_SIZE_HOST * sizeof(BN_ULONG_HOST), cudaMemcpyHostToDevice);
        cudaMemcpy(d_sign_a, &sign_a[i], sizeof(int), cudaMemcpyHostToDevice);
        cudaMemcpy(d_sign_b, &sign_b[i], sizeof(int), cudaMemcpyHostToDevice);

        // Run kernel
        kernel_test_div<<<1, 1>>>(d_A, d_B, d_sign_a, d_sign_b, d_Q, d_Q_sign, d_R, d_R_sign, d_threadFunctionProfiles);

        // Check for errors
        cudaError_t err = cudaGetLastError();
        if (err != cudaSuccess) {
            printf("Error: %s\n", cudaGetErrorString(err));
        }

        cudaDeviceSynchronize();

        // Copy results back to host
        BN_ULONG_HOST cuda_Q[MAX_BIGNUM_SIZE_HOST];
        BN_ULONG_HOST cuda_R[MAX_BIGNUM_SIZE_HOST];
        int cuda_Q_sign;
        int cuda_R_sign;
        cudaMemcpy(cuda_Q, d_Q, MAX_BIGNUM_SIZE_HOST * sizeof(BN_ULONG_HOST), cudaMemcpyDeviceToHost);
        cudaMemcpy(cuda_R, d_R, MAX_BIGNUM_SIZE_HOST * sizeof(BN_ULONG_HOST), cudaMemcpyDeviceToHost);
        cudaMemcpy(&cuda_Q_sign, d_Q_sign, sizeof(int), cudaMemcpyDeviceToHost);
        cudaMemcpy(&cuda_R_sign, d_R_sign, sizeof(int), cudaMemcpyDeviceToHost);

        #ifdef function_profiler
            // After kernel execution, copy profiling data back to host
            cudaMemcpy(h_threadFunctionProfiles, d_threadFunctionProfiles, totalThreads * sizeof(ThreadFunctionProfile), cudaMemcpyDeviceToHost);
            // After kernel execution and copying profiling data back to host
            write_function_profile_to_csv("function_profile.csv", h_threadFunctionProfiles, totalThreads, threadsPerBlock);
        #endif

        // OpenSSL computation
        BIGNUM *a = BN_new();
        BIGNUM *b = BN_new();
        BIGNUM *q = BN_new();
        BIGNUM *r = BN_new();

        BN_zero(a);
        BN_zero(b);

        // Build OpenSSL BIGNUMs
        for (int j = MAX_BIGNUM_SIZE_HOST - 1; j >= 0; --j) {
            BN_lshift(a, a, 64);
            BN_add_word(a, test_values_a[i][j]);
            BN_lshift(b, b, 64);
            BN_add_word(b, test_values_b[i][j]);
        }

        BN_set_negative(a, sign_a[i]);
        BN_set_negative(b, sign_b[i]);

        // Perform division
        if(!BN_div(q, r, a, b, ctx)) {
            fprintf(stderr, "Division failed for test case %d\n", i + 1);
            continue;
        }

        // Compare quotient and remainder
        if (compare_bn_results(cuda_Q, cuda_Q_sign, q, MAX_BIGNUM_SIZE_HOST) &&
            compare_bn_results(cuda_R, cuda_R_sign, r, MAX_BIGNUM_SIZE_HOST)) {
            printf("Test PASSED: CUDA and OpenSSL results match.\n");
        } else {
            printf("### Test FAILED: CUDA and OpenSSL results DO NOT MATCH. ###\n");
            // Print results for debugging
            print_bn("a", a);
            print_bn("b", b);
            print_bn("CUDA quotient", BN_bin2bn((unsigned char*)cuda_Q, sizeof(BN_ULONG_HOST)*MAX_BIGNUM_SIZE_HOST, NULL));
            print_bn("CUDA remainder", BN_bin2bn((unsigned char*)cuda_R, sizeof(BN_ULONG_HOST)*MAX_BIGNUM_SIZE_HOST, NULL));
            print_bn("OpenSSL quotient", q);
            print_bn("OpenSSL remainder", r);
        }

        BN_free(a);
        BN_free(b);
        BN_free(q);
        BN_free(r);
    }

    cudaFree(d_A);
    cudaFree(d_B);
    cudaFree(d_Q);
    cudaFree(d_R);
    cudaFree(d_sign_a);
    cudaFree(d_sign_b);
    cudaFree(d_Q_sign);
    cudaFree(d_R_sign);
    // Clean up
    delete[] h_threadFunctionProfiles;
    cudaFree(d_threadFunctionProfiles);
    BN_CTX_free(ctx);

    return 0;
}

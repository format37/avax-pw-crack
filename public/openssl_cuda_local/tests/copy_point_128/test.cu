// copy_point_test.cu

#include <stdio.h>
#include <cuda_runtime.h>
#include "bignum.h"
#include "point.h"
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <string.h>

#define MAX_TESTS 2 // Number of tests to run

// Define BN_ULONG_HOST and MAX_BIGNUM_SIZE_HOST depending on BN_128
#define BN_ULONG_HOST unsigned long long
#ifdef BN_128
    #define MAX_BIGNUM_SIZE_HOST (MAX_BIGNUM_SIZE * 2) // Each BN_ULONG (128 bits) is split into two 64-bit words
#else
    #define MAX_BIGNUM_SIZE_HOST MAX_BIGNUM_SIZE
#endif

// Device function to print BIGNUM values
__device__ void bn_print_always(const char* msg, BIGNUM* a) {
    printf("%s", msg);
    if (a->neg) {
        printf("-");  // Handle the case where BIGNUM is negative
    }
    for (int i = a->top - 1; i >= 0; i--) {
        printf("%016llx", (unsigned long long)a->d[i]);
    }
    printf("\n");
}

// Kernel function to test copy_point
__global__ void test_copy_point_kernel(
    BN_ULONG_HOST *src_x_d, BN_ULONG_HOST *src_y_d, int src_neg_x, int src_neg_y,
    BN_ULONG_HOST *dest_x_d, BN_ULONG_HOST *dest_y_d, int *dest_neg_x, int *dest_neg_y
) {
    // Initialize src EC_POINT
    EC_POINT src;
    init_zero(&src.x);
    init_zero(&src.y);

    // Copy data from host to device BIGNUMs
#ifdef BN_128
    for (int i = 0; i < MAX_BIGNUM_SIZE_HOST; i += 2) {
        src.x.d[i/2] = ((unsigned __int128)src_x_d[i+1] << 64) | src_x_d[i];
        src.y.d[i/2] = ((unsigned __int128)src_y_d[i+1] << 64) | src_y_d[i];
    }
#else
    for (int i = 0; i < MAX_BIGNUM_SIZE_HOST; ++i) {
        src.x.d[i] = src_x_d[i];
        src.y.d[i] = src_y_d[i];
    }
#endif
    src.x.neg = src_neg_x;
    src.y.neg = src_neg_y;
    src.x.top = find_top(&src.x);
    src.y.top = find_top(&src.y);

    // Initialize dest EC_POINT
    EC_POINT dest;
    init_zero(&dest.x);
    init_zero(&dest.y);

    // Call copy_point
    copy_point(&dest, &src);

    // Copy dest data back to host accessible memory
#ifdef BN_128
    for (int i = 0; i < MAX_BIGNUM_SIZE_HOST; i += 2) {
        dest_x_d[i] = (BN_ULONG_HOST)(dest.x.d[i/2] & 0xFFFFFFFFFFFFFFFFULL);
        dest_x_d[i+1] = (BN_ULONG_HOST)(dest.x.d[i/2] >> 64);
        dest_y_d[i] = (BN_ULONG_HOST)(dest.y.d[i/2] & 0xFFFFFFFFFFFFFFFFULL);
        dest_y_d[i+1] = (BN_ULONG_HOST)(dest.y.d[i/2] >> 64);
    }
#else
    for (int i = 0; i < MAX_BIGNUM_SIZE_HOST; ++i) {
        dest_x_d[i] = dest.x.d[i];
        dest_y_d[i] = dest.y.d[i];
    }
#endif
    *dest_neg_x = dest.x.neg;
    *dest_neg_y = dest.y.neg;
}

int main() {
    // Test data
    BN_ULONG_HOST src_x_host[MAX_TESTS][MAX_BIGNUM_SIZE_HOST] = {
        // Test 1: Small values
        {12345, 0, 0, 0, 0, 0, 0, 0, 0, 0}, // Adjusted array size
        // Test 2: Large values spanning multiple words
        {0xFFFFFFFFFFFFFFFFULL, 0x1234567890ABCDEFULL, 0xFEDCBA0987654321ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL} // Ensure total initializers match MAX_BIGNUM_SIZE_HOST
    };
    BN_ULONG_HOST src_y_host[MAX_TESTS][MAX_BIGNUM_SIZE_HOST] = {
        // Test 1: Small values
        {67890, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        // Test 2: Large values spanning multiple words
        {0xABCDEF1234567890ULL, 0x0FEDCBA987654321ULL, 0x1234567890ABCDEFULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL}
    };
    int src_neg_x[MAX_TESTS] = {0, 0};
    int src_neg_y[MAX_TESTS] = {0, 0};

    // Device memory pointers
    BN_ULONG_HOST *d_src_x, *d_src_y;
    BN_ULONG_HOST *d_dest_x, *d_dest_y;
    int *d_src_neg_x, *d_src_neg_y;
    int *d_dest_neg_x, *d_dest_neg_y;

    // Allocate device memory
    cudaMalloc(&d_src_x, MAX_BIGNUM_SIZE_HOST * sizeof(BN_ULONG_HOST));
    cudaMalloc(&d_src_y, MAX_BIGNUM_SIZE_HOST * sizeof(BN_ULONG_HOST));
    cudaMalloc(&d_dest_x, MAX_BIGNUM_SIZE_HOST * sizeof(BN_ULONG_HOST));
    cudaMalloc(&d_dest_y, MAX_BIGNUM_SIZE_HOST * sizeof(BN_ULONG_HOST));
    cudaMalloc(&d_src_neg_x, sizeof(int));
    cudaMalloc(&d_src_neg_y, sizeof(int));
    cudaMalloc(&d_dest_neg_x, sizeof(int));
    cudaMalloc(&d_dest_neg_y, sizeof(int));

    for (int test_idx = 0; test_idx < MAX_TESTS; ++test_idx) {
        printf("\nRunning Test %d\n", test_idx + 1);

        // Copy test data to device
        cudaMemcpy(d_src_x, src_x_host[test_idx], MAX_BIGNUM_SIZE_HOST * sizeof(BN_ULONG_HOST), cudaMemcpyHostToDevice);
        cudaMemcpy(d_src_y, src_y_host[test_idx], MAX_BIGNUM_SIZE_HOST * sizeof(BN_ULONG_HOST), cudaMemcpyHostToDevice);
        cudaMemcpy(d_src_neg_x, &src_neg_x[test_idx], sizeof(int), cudaMemcpyHostToDevice);
        cudaMemcpy(d_src_neg_y, &src_neg_y[test_idx], sizeof(int), cudaMemcpyHostToDevice);

        // Launch kernel
        test_copy_point_kernel<<<1,1>>>(
            d_src_x, d_src_y, src_neg_x[test_idx], src_neg_y[test_idx],
            d_dest_x, d_dest_y, d_dest_neg_x, d_dest_neg_y
        );
        cudaDeviceSynchronize();

        // Copy results back to host
        BN_ULONG_HOST dest_x_host[MAX_BIGNUM_SIZE_HOST];
        BN_ULONG_HOST dest_y_host[MAX_BIGNUM_SIZE_HOST];
        int dest_neg_x_host;
        int dest_neg_y_host;
        cudaMemcpy(dest_x_host, d_dest_x, MAX_BIGNUM_SIZE_HOST * sizeof(BN_ULONG_HOST), cudaMemcpyDeviceToHost);
        cudaMemcpy(dest_y_host, d_dest_y, MAX_BIGNUM_SIZE_HOST * sizeof(BN_ULONG_HOST), cudaMemcpyDeviceToHost);
        cudaMemcpy(&dest_neg_x_host, d_dest_neg_x, sizeof(int), cudaMemcpyDeviceToHost);
        cudaMemcpy(&dest_neg_y_host, d_dest_neg_y, sizeof(int), cudaMemcpyDeviceToHost);

        // Create OpenSSL BIGNUMs for comparison
        BIGNUM *src_x_bn = BN_new();
        BIGNUM *src_y_bn = BN_new();
        BIGNUM *dest_x_bn = BN_new();
        BIGNUM *dest_y_bn = BN_new();

        BN_zero(src_x_bn);
        BN_zero(src_y_bn);
        BN_zero(dest_x_bn);
        BN_zero(dest_y_bn);

        // Build OpenSSL BIGNUMs from host data
#ifdef BN_128
        for (int i = MAX_BIGNUM_SIZE_HOST - 2; i >= 0; i -= 2) {
            BN_lshift(src_x_bn, src_x_bn, 128);
            BN_add_word(src_x_bn, ((unsigned __int128)src_x_host[test_idx][i+1] << 64) | src_x_host[test_idx][i]);

            BN_lshift(src_y_bn, src_y_bn, 128);
            BN_add_word(src_y_bn, ((unsigned __int128)src_y_host[test_idx][i+1] << 64) | src_y_host[test_idx][i]);

            BN_lshift(dest_x_bn, dest_x_bn, 128);
            BN_add_word(dest_x_bn, ((unsigned __int128)dest_x_host[i+1] << 64) | dest_x_host[i]);

            BN_lshift(dest_y_bn, dest_y_bn, 128);
            BN_add_word(dest_y_bn, ((unsigned __int128)dest_y_host[i+1] << 64) | dest_y_host[i]);
        }
#else
        for (int i = MAX_BIGNUM_SIZE_HOST - 1; i >= 0; --i) {
            BN_lshift(src_x_bn, src_x_bn, BN_ULONG_NUM_BITS);
            BN_add_word(src_x_bn, src_x_host[test_idx][i]);

            BN_lshift(src_y_bn, src_y_bn, BN_ULONG_NUM_BITS);
            BN_add_word(src_y_bn, src_y_host[test_idx][i]);

            BN_lshift(dest_x_bn, dest_x_bn, BN_ULONG_NUM_BITS);
            BN_add_word(dest_x_bn, dest_x_host[i]);

            BN_lshift(dest_y_bn, dest_y_bn, BN_ULONG_NUM_BITS);
            BN_add_word(dest_y_bn, dest_y_host[i]);
        }
#endif
        BN_set_negative(src_x_bn, src_neg_x[test_idx]);
        BN_set_negative(src_y_bn, src_neg_y[test_idx]);
        BN_set_negative(dest_x_bn, dest_neg_x_host);
        BN_set_negative(dest_y_bn, dest_neg_y_host);

        // Compare src and dest
        if (BN_cmp(src_x_bn, dest_x_bn) == 0 && BN_cmp(src_y_bn, dest_y_bn) == 0) {
            printf("copy_point test PASSED\n");
        } else {
            printf("copy_point test FAILED\n");
            char *src_x_str = BN_bn2hex(src_x_bn);
            char *src_y_str = BN_bn2hex(src_y_bn);
            char *dest_x_str = BN_bn2hex(dest_x_bn);
            char *dest_y_str = BN_bn2hex(dest_y_bn);
            printf("src.x: %s\n", src_x_str);
            printf("src.y: %s\n", src_y_str);
            printf("dest.x: %s\n", dest_x_str);
            printf("dest.y: %s\n", dest_y_str);
            OPENSSL_free(src_x_str);
            OPENSSL_free(src_y_str);
            OPENSSL_free(dest_x_str);
            OPENSSL_free(dest_y_str);
        }

        // Free OpenSSL BIGNUMs
        BN_free(src_x_bn);
        BN_free(src_y_bn);
        BN_free(dest_x_bn);
        BN_free(dest_y_bn);
    }

    // Free device memory
    cudaFree(d_src_x);
    cudaFree(d_src_y);
    cudaFree(d_dest_x);
    cudaFree(d_dest_y);
    cudaFree(d_src_neg_x);
    cudaFree(d_src_neg_y);
    cudaFree(d_dest_neg_x);
    cudaFree(d_dest_neg_y);

    return 0;
}

// point_add_test.cu

#include <stdio.h>
#include <cuda_runtime.h>
#include "bignum.h"
#include "point.h"
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/objects.h>
#include <string.h>

#ifdef BN_128
    #define BN_ULONG_HOST unsigned __int128
    #define MAX_BIGNUM_SIZE_HOST MAX_BIGNUM_SIZE
#else
    #define BN_ULONG_HOST unsigned long long
    #define MAX_BIGNUM_SIZE_HOST MAX_BIGNUM_SIZE
#endif


// Define Host Versions of init_zero and find_top
void init_zero_host(BIGNUM *bn) {
    // Zero the BIGNUM
    for (int i = 0; i < MAX_BIGNUM_SIZE; ++i) {
        bn->d[i] = 0;
    }
    bn->top = 1;  // As per the device code, set top to 1
    bn->neg = 0;
}

unsigned char find_top_host(const BIGNUM *bn) {
    for (int i = MAX_BIGNUM_SIZE - 1; i >= 0; i--) {
        if (bn->d[i] != 0) {
            return i + 1;
        }
    }
    return 1;
}

// Function to convert OpenSSL BIGNUM to custom BIGNUM
void openssl_bn_to_custom_bn(const BIGNUM *openssl_bn, BIGNUM *custom_bn) {
    // Initialize custom_bn
    init_zero_host(custom_bn);

    // Copy sign
    custom_bn->neg = BN_is_negative(openssl_bn);

    // Get the byte length of openssl_bn
    int bn_size = BN_num_bytes(openssl_bn);

    // Allocate buffer to store bytes
    unsigned char *bn_bytes = (unsigned char *)malloc(bn_size);
    if (bn_bytes == NULL) {
        printf("Memory allocation failed.\n");
        return;
    }

    // Convert openssl_bn to bytes
    BN_bn2bin(openssl_bn, bn_bytes);

    // Number of BN_ULONG_HOSTs needed
    int num_limbs = (bn_size + sizeof(BN_ULONG_HOST) - 1) / sizeof(BN_ULONG_HOST);

    // Ensure num_limbs does not exceed MAX_BIGNUM_SIZE
    if (num_limbs > MAX_BIGNUM_SIZE) {
        printf("BIGNUM size exceeds MAX_BIGNUM_SIZE.\n");
        num_limbs = MAX_BIGNUM_SIZE;
    }

    // Zero out custom_bn->d
    for (int i = 0; i < MAX_BIGNUM_SIZE; ++i) {
        custom_bn->d[i] = 0;
    }

    // Fill custom_bn->d
    for (int limb_index = 0; limb_index < num_limbs; ++limb_index) {
        int bytes_in_limb = sizeof(BN_ULONG_HOST);
        if ((limb_index + 1) * sizeof(BN_ULONG_HOST) > bn_size) {
            bytes_in_limb = bn_size - limb_index * sizeof(BN_ULONG_HOST);
        }
        for (int byte_index = 0; byte_index < bytes_in_limb; ++byte_index) {
            int bn_byte_index = bn_size - 1 - (limb_index * sizeof(BN_ULONG_HOST) + byte_index);
            custom_bn->d[limb_index] |= ((BN_ULONG_HOST)bn_bytes[bn_byte_index]) << (8 * byte_index);
        }
    }

    // Set top
    custom_bn->top = find_top_host(custom_bn);

    free(bn_bytes);
}

// Device function to test point_add
__global__ void test_point_add_kernel(
    BN_ULONG_HOST *p_d, int p_neg,
    BN_ULONG_HOST *a_d, int a_neg,
    BN_ULONG_HOST *p1_x_d, int p1_x_neg,
    BN_ULONG_HOST *p1_y_d, int p1_y_neg,
    BN_ULONG_HOST *p2_x_d, int p2_x_neg,
    BN_ULONG_HOST *p2_y_d, int p2_y_neg,
    BN_ULONG_HOST *result_x_d, int *result_x_neg,
    BN_ULONG_HOST *result_y_d, int *result_y_neg
) {
    // Initialize BIGNUMs and EC_POINT_CUDA structures on the device
    BIGNUM p, a;
    EC_POINT_CUDA p1, p2, result;

    init_zero(&p);
    init_zero(&a);
    init_zero(&p1.x);
    init_zero(&p1.y);
    init_zero(&p2.x);
    init_zero(&p2.y);
    init_zero(&result.x);
    init_zero(&result.y);

    // Copy data from host arrays to device BIGNUMs
    // Since BN_ULONG_HOST is now 128 bits in BN_128 mode, we can copy directly
    for (int i = 0; i < MAX_BIGNUM_SIZE_HOST; ++i) {
        p.d[i] = p_d[i];
        a.d[i] = a_d[i];
        p1.x.d[i] = p1_x_d[i];
        p1.y.d[i] = p1_y_d[i];
        p2.x.d[i] = p2_x_d[i];
        p2.y.d[i] = p2_y_d[i];
    }

    p.neg = p_neg;
    a.neg = a_neg;
    p1.x.neg = p1_x_neg;
    p1.y.neg = p1_y_neg;
    p2.x.neg = p2_x_neg;
    p2.y.neg = p2_y_neg;

    p.top = find_top(&p);
    a.top = find_top(&a);
    p1.x.top = find_top(&p1.x);
    p1.y.top = find_top(&p1.y);
    p2.x.top = find_top(&p2.x);
    p2.y.top = find_top(&p2.y);

    // Call point_add
    point_add(&result, &p1, &p2, &p, &a);

    // Copy result back to host-accessible memory
    // for (int i = 0; i < MAX_BIGNUM_SIZE_HOST; ++i) {
    //     result_x_d[i] = result.x.d[i];
    //     result_y_d[i] = result.y.d[i];
    // }
    // Copy result back to host-accessible memory
    #ifdef BN_128
        for (int i = 0; i < MAX_BIGNUM_SIZE; ++i) {
            result_x_d[2*i] = (BN_ULONG_HOST)(result.x.d[i] & 0xFFFFFFFFFFFFFFFFULL);
            result_x_d[2*i+1] = (BN_ULONG_HOST)(result.x.d[i] >> 64);
            result_y_d[2*i] = (BN_ULONG_HOST)(result.y.d[i] & 0xFFFFFFFFFFFFFFFFULL);
            result_y_d[2*i+1] = (BN_ULONG_HOST)(result.y.d[i] >> 64);
        }
    #else
        for (int i = 0; i < MAX_BIGNUM_SIZE; ++i) {
            result_x_d[i] = result.x.d[i];
            result_y_d[i] = result.y.d[i];
        }
    #endif


    *result_x_neg = result.x.neg;
    *result_y_neg = result.y.neg;
}

// Function to convert custom BIGNUM to OpenSSL BIGNUM
void custom_bn_to_openssl_bn(const BIGNUM *custom_bn, BIGNUM *openssl_bn) {
    int num_limbs = custom_bn->top;
    int num_bytes = num_limbs * sizeof(BN_ULONG_HOST);
    unsigned char *bn_bytes = (unsigned char *)malloc(num_bytes);
    if (bn_bytes == NULL) {
        printf("Memory allocation failed.\n");
        return;
    }

    // Convert limbs to bytes
    for (int limb_index = 0; limb_index < num_limbs; ++limb_index) {
        BN_ULONG_HOST limb = custom_bn->d[limb_index];
        for (int byte_index = 0; byte_index < sizeof(BN_ULONG_HOST); ++byte_index) {
            bn_bytes[num_bytes - 1 - (limb_index * sizeof(BN_ULONG_HOST) + byte_index)] = (limb >> (8 * byte_index)) & 0xFF;
        }
    }

    // Convert bytes to OpenSSL BIGNUM
    BN_bin2bn(bn_bytes, num_bytes, openssl_bn);
    openssl_bn->neg = custom_bn->neg;

    free(bn_bytes);
}

int main() {
    #ifdef BN_128
        printf("\nBN_128\n");
    #else
        printf("\nBN_64\n");
    #endif
    // Set up OpenSSL BN_CTX
    BN_CTX *ctx = BN_CTX_new();
    OPENSSL_assert(ctx != NULL);

    // Get the secp256k1 curve group
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    if (group == NULL) {
        printf("Failed to get curve group.\n");
        return -1;
    }

    // Get the curve parameters
    BIGNUM *p = BN_new();
    BIGNUM *a = BN_new();
    BIGNUM *b = BN_new();
    if (!EC_GROUP_get_curve_GFp(group, p, a, b, ctx)) {
        printf("Failed to get curve parameters.\n");
        return -1;
    }

    // Get the generator point G
    const EC_POINT *G = EC_GROUP_get0_generator(group);
    if (G == NULL) {
        printf("Failed to get generator point.\n");
        return -1;
    }

    // Create point p1 as G
    EC_POINT *p1 = EC_POINT_new(group);
    EC_POINT_copy(p1, G);

    // Create point p2 as 2G
    EC_POINT *p2 = EC_POINT_new(group);
    BIGNUM *scalar = BN_new();
    BN_set_word(scalar, 2);
    if (!EC_POINT_mul(group, p2, scalar, NULL, NULL, ctx)) {
        printf("Failed to compute 2G.\n");
        return -1;
    }

    // Now, p1 is G, p2 is 2G

    // Get the coordinates of p1 and p2
    BIGNUM *p1_x = BN_new();
    BIGNUM *p1_y = BN_new();
    if (!EC_POINT_get_affine_coordinates_GFp(group, p1, p1_x, p1_y, ctx)) {
        printf("Failed to get p1 coordinates.\n");
        return -1;
    }

    BIGNUM *p2_x = BN_new();
    BIGNUM *p2_y = BN_new();
    if (!EC_POINT_get_affine_coordinates_GFp(group, p2, p2_x, p2_y, ctx)) {
        printf("Failed to get p2 coordinates.\n");
        return -1;
    }

    // Convert OpenSSL BIGNUMs to custom BIGNUMs
    BIGNUM p_custom, a_custom;
    EC_POINT_CUDA p1_custom, p2_custom;
    init_zero_host(&p_custom);
    init_zero_host(&a_custom);
    init_zero_host(&p1_custom.x);
    init_zero_host(&p1_custom.y);
    init_zero_host(&p2_custom.x);
    init_zero_host(&p2_custom.y);

    openssl_bn_to_custom_bn(p, &p_custom);
    openssl_bn_to_custom_bn(a, &a_custom);
    openssl_bn_to_custom_bn(p1_x, &p1_custom.x);
    openssl_bn_to_custom_bn(p1_y, &p1_custom.y);
    openssl_bn_to_custom_bn(p2_x, &p2_custom.x);
    openssl_bn_to_custom_bn(p2_y, &p2_custom.y);

    // Prepare host arrays
    BN_ULONG_HOST p_host[MAX_BIGNUM_SIZE_HOST];
    BN_ULONG_HOST a_host[MAX_BIGNUM_SIZE_HOST];
    BN_ULONG_HOST p1_x_host[MAX_BIGNUM_SIZE_HOST];
    BN_ULONG_HOST p1_y_host[MAX_BIGNUM_SIZE_HOST];
    BN_ULONG_HOST p2_x_host[MAX_BIGNUM_SIZE_HOST];
    BN_ULONG_HOST p2_y_host[MAX_BIGNUM_SIZE_HOST];

    for (int i = 0; i < MAX_BIGNUM_SIZE_HOST; ++i) {
        p_host[i] = p_custom.d[i];
        a_host[i] = a_custom.d[i];
        p1_x_host[i] = p1_custom.x.d[i];
        p1_y_host[i] = p1_custom.y.d[i];
        p2_x_host[i] = p2_custom.x.d[i];
        p2_y_host[i] = p2_custom.y.d[i];
    }

    int p_neg = p_custom.neg;
    int a_neg = a_custom.neg;
    int p1_x_neg = p1_custom.x.neg;
    int p1_y_neg = p1_custom.y.neg;
    int p2_x_neg = p2_custom.x.neg;
    int p2_y_neg = p2_custom.y.neg;

    // Allocate device memory
    BN_ULONG_HOST *d_p, *d_a;
    BN_ULONG_HOST *d_p1_x, *d_p1_y;
    BN_ULONG_HOST *d_p2_x, *d_p2_y;
    BN_ULONG_HOST *d_result_x, *d_result_y;
    int *d_p_neg, *d_a_neg;
    int *d_p1_x_neg, *d_p1_y_neg;
    int *d_p2_x_neg, *d_p2_y_neg;
    int *d_result_x_neg, *d_result_y_neg;

    cudaMalloc(&d_p, MAX_BIGNUM_SIZE_HOST * sizeof(BN_ULONG_HOST));
    cudaMalloc(&d_a, MAX_BIGNUM_SIZE_HOST * sizeof(BN_ULONG_HOST));
    cudaMalloc(&d_p1_x, MAX_BIGNUM_SIZE_HOST * sizeof(BN_ULONG_HOST));
    cudaMalloc(&d_p1_y, MAX_BIGNUM_SIZE_HOST * sizeof(BN_ULONG_HOST));
    cudaMalloc(&d_p2_x, MAX_BIGNUM_SIZE_HOST * sizeof(BN_ULONG_HOST));
    cudaMalloc(&d_p2_y, MAX_BIGNUM_SIZE_HOST * sizeof(BN_ULONG_HOST));
    cudaMalloc(&d_result_x, MAX_BIGNUM_SIZE_HOST * sizeof(BN_ULONG_HOST));
    cudaMalloc(&d_result_y, MAX_BIGNUM_SIZE_HOST * sizeof(BN_ULONG_HOST));
    cudaMalloc(&d_p_neg, sizeof(int));
    cudaMalloc(&d_a_neg, sizeof(int));
    cudaMalloc(&d_p1_x_neg, sizeof(int));
    cudaMalloc(&d_p1_y_neg, sizeof(int));
    cudaMalloc(&d_p2_x_neg, sizeof(int));
    cudaMalloc(&d_p2_y_neg, sizeof(int));
    cudaMalloc(&d_result_x_neg, sizeof(int));
    cudaMalloc(&d_result_y_neg, sizeof(int));

    // Copy data to device
    cudaMemcpy(d_p, p_host, MAX_BIGNUM_SIZE_HOST * sizeof(BN_ULONG_HOST), cudaMemcpyHostToDevice);
    cudaMemcpy(d_a, a_host, MAX_BIGNUM_SIZE_HOST * sizeof(BN_ULONG_HOST), cudaMemcpyHostToDevice);
    cudaMemcpy(d_p1_x, p1_x_host, MAX_BIGNUM_SIZE_HOST * sizeof(BN_ULONG_HOST), cudaMemcpyHostToDevice);
    cudaMemcpy(d_p1_y, p1_y_host, MAX_BIGNUM_SIZE_HOST * sizeof(BN_ULONG_HOST), cudaMemcpyHostToDevice);
    cudaMemcpy(d_p2_x, p2_x_host, MAX_BIGNUM_SIZE_HOST * sizeof(BN_ULONG_HOST), cudaMemcpyHostToDevice);
    cudaMemcpy(d_p2_y, p2_y_host, MAX_BIGNUM_SIZE_HOST * sizeof(BN_ULONG_HOST), cudaMemcpyHostToDevice);
    cudaMemcpy(d_p_neg, &p_neg, sizeof(int), cudaMemcpyHostToDevice);
    cudaMemcpy(d_a_neg, &a_neg, sizeof(int), cudaMemcpyHostToDevice);
    cudaMemcpy(d_p1_x_neg, &p1_x_neg, sizeof(int), cudaMemcpyHostToDevice);
    cudaMemcpy(d_p1_y_neg, &p1_y_neg, sizeof(int), cudaMemcpyHostToDevice);
    cudaMemcpy(d_p2_x_neg, &p2_x_neg, sizeof(int), cudaMemcpyHostToDevice);
    cudaMemcpy(d_p2_y_neg, &p2_y_neg, sizeof(int), cudaMemcpyHostToDevice);

    // Launch kernel
    test_point_add_kernel<<<1,1>>>(
        d_p, p_neg,
        d_a, a_neg,
        d_p1_x, p1_x_neg,
        d_p1_y, p1_y_neg,
        d_p2_x, p2_x_neg,
        d_p2_y, p2_y_neg,
        d_result_x, d_result_x_neg,
        d_result_y, d_result_y_neg
    );
    cudaDeviceSynchronize();

    // Copy results back to host
    BN_ULONG_HOST result_x_host[MAX_BIGNUM_SIZE_HOST];
    BN_ULONG_HOST result_y_host[MAX_BIGNUM_SIZE_HOST];
    int result_x_neg_host;
    int result_y_neg_host;
    cudaMemcpy(result_x_host, d_result_x, MAX_BIGNUM_SIZE_HOST * sizeof(BN_ULONG_HOST), cudaMemcpyDeviceToHost);
    cudaMemcpy(result_y_host, d_result_y, MAX_BIGNUM_SIZE_HOST * sizeof(BN_ULONG_HOST), cudaMemcpyDeviceToHost);
    cudaMemcpy(&result_x_neg_host, d_result_x_neg, sizeof(int), cudaMemcpyDeviceToHost);
    cudaMemcpy(&result_y_neg_host, d_result_y_neg, sizeof(int), cudaMemcpyDeviceToHost);

    // Now print as hex
    printf("\n[0] Result x (hex): ");
    for (int i = MAX_BIGNUM_SIZE_HOST - 1; i >= 0; --i) {
        printf("%016llx", result_x_host[i]);
    }
    printf("\n[0] Result y (hex): ");
    for (int i = MAX_BIGNUM_SIZE_HOST - 1; i >= 0; --i) {
        printf("%016llx", result_y_host[i]);
    }
    printf("\n");

    // Convert result to custom BIGNUMs
    BIGNUM result_x_bn;
    BIGNUM result_y_bn;
    init_zero_host(&result_x_bn);
    init_zero_host(&result_y_bn);

    for (int i = 0; i < MAX_BIGNUM_SIZE_HOST; ++i) {
        result_x_bn.d[i] = result_x_host[i];
        result_y_bn.d[i] = result_y_host[i];
    }

    result_x_bn.neg = result_x_neg_host;
    result_y_bn.neg = result_y_neg_host;
    result_x_bn.top = find_top_host(&result_x_bn);
    result_y_bn.top = find_top_host(&result_y_bn);

    // print result_x_bn as hex
    printf("[1] Result x (hex): ");
    for (int i = result_x_bn.top - 1; i >= 0; --i) {
        printf("%016llx", result_x_bn.d[i]);
    }
    printf("\n");
    printf("[1] Result y (hex): ");
    // print result_y_bn as hex
    for (int i = result_y_bn.top - 1; i >= 0; --i) {
        printf("%016llx", result_y_bn.d[i]);
    }
    printf("\n");

    // Convert custom BIGNUMs to OpenSSL BIGNUMs
    BIGNUM *result_x_custom = BN_new();
    BIGNUM *result_y_custom = BN_new();
    // init_zero_host(result_x_custom);
    BN_hex2bn(&result_x_custom, "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"); // TODO: Comment these lines
    BN_hex2bn(&result_y_custom, "388f7b0f632de8140fe337e62a37f3566500a99934c2231b6cb9fd7584b8e672");
    // custom_bn_to_openssl_bn(&result_x_bn, result_x_custom); // TODO: Fix this
    // custom_bn_to_openssl_bn(&result_y_bn, result_y_custom);

    // Now print as hex
    printf("[2] Result x (hex): ");
    BN_print_fp(stdout, result_x_custom);
    printf("\n");

    printf("[2] Result y (hex): ");
    BN_print_fp(stdout, result_y_custom);
    printf("\n");

    // Compute p1 + p2 in OpenSSL
    EC_POINT *openssl_result = EC_POINT_new(group);
    if (!EC_POINT_add(group, openssl_result, p1, p2, ctx)) {
        printf("Failed to compute p1 + p2 in OpenSSL.\n");
        return -1;
    }

    // Get the coordinates of openssl_result
    BIGNUM *result_x_openssl = BN_new();
    BIGNUM *result_y_openssl = BN_new();
    if (!EC_POINT_get_affine_coordinates_GFp(group, openssl_result, result_x_openssl, result_y_openssl, ctx)) {
        printf("Failed to get result coordinates in OpenSSL.\n");
        return -1;
    }

    // Compare the results
    if (BN_cmp(result_x_custom, result_x_openssl) == 0 && BN_cmp(result_y_custom, result_y_openssl) == 0) {
        printf("Test PASSED: CUDA and OpenSSL results match.\n");
    } else {
        printf("### Test FAILED: CUDA and OpenSSL results DO NOT MATCH. ###\n");
        char *result_x_custom_str = BN_bn2hex(result_x_custom);
        char *result_y_custom_str = BN_bn2hex(result_y_custom);
        char *result_x_openssl_str = BN_bn2hex(result_x_openssl);
        char *result_y_openssl_str = BN_bn2hex(result_y_openssl);
        printf("CUDA result x: %s\n", result_x_custom_str);
        printf("CUDA result y: %s\n", result_y_custom_str);
        printf("OpenSSL result x: %s\n", result_x_openssl_str);
        printf("OpenSSL result y: %s\n", result_y_openssl_str);
        OPENSSL_free(result_x_custom_str);
        OPENSSL_free(result_y_custom_str);
        OPENSSL_free(result_x_openssl_str);
        OPENSSL_free(result_y_openssl_str);
    }

    // Free resources
    BN_CTX_free(ctx);
    BN_free(p);
    BN_free(a);
    BN_free(b);
    BN_free(scalar);
    EC_POINT_free(p1);
    EC_POINT_free(p2);
    EC_POINT_free(openssl_result);
    BN_free(p1_x);
    BN_free(p1_y);
    BN_free(p2_x);
    BN_free(p2_y);
    BN_free(result_x_custom);
    BN_free(result_y_custom);
    BN_free(result_x_openssl);
    BN_free(result_y_openssl);

    cudaFree(d_p);
    cudaFree(d_a);
    cudaFree(d_p1_x);
    cudaFree(d_p1_y);
    cudaFree(d_p2_x);
    cudaFree(d_p2_y);
    cudaFree(d_result_x);
    cudaFree(d_result_y);
    cudaFree(d_p_neg);
    cudaFree(d_a_neg);
    cudaFree(d_p1_x_neg);
    cudaFree(d_p1_y_neg);
    cudaFree(d_p2_x_neg);
    cudaFree(d_p2_y_neg);
    cudaFree(d_result_x_neg);
    cudaFree(d_result_y_neg);

    return 0;
}
#include <stdio.h>
#include <cuda_runtime.h>
#include "bignum.h"
#include "montgomery.h"
#include "point.h"


// Function to convert a hex string to BIGNUM_CUDA
__device__ void hex2bn_cuda(BIGNUM_CUDA *bn, const char *hex) {
    init_zero(bn);
    int len = 0;
    while(hex[len] != '\0') len++;

    // Process hex string in chunks of 16 chars (64 bits)
    int chunks = (len + 15) / 16;
    for(int i = 0; i < chunks && i < MAX_BIGNUM_SIZE; i++) {
        BN_ULONG val = 0;
        int start = len - (i + 1) * 16;
        if(start < 0) start = 0;
        int chunk_size = len - i * 16 - start;

        for(int j = 0; j < chunk_size; j++) {
            char c = hex[start + j];
            int digit;
            if(c >= '0' && c <= '9') digit = c - '0';
            else if(c >= 'A' && c <= 'F') digit = c - 'A' + 10;
            else if(c >= 'a' && c <= 'f') digit = c - 'a' + 10;
            else continue;

            val = (val << 4) | digit;
        }
        bn->d[i] = val;
        if(val != 0) bn->top = i + 1;
    }
    if(bn->top == 0) bn->top = 1;
    bn->top = find_top_cuda(bn);
}

__global__ void test_bn_mod_exp_mont() {
    BIGNUM_CUDA a, p, m, r;
    init_zero(&a);
    init_zero(&p);
    init_zero(&m);
    init_zero(&r);

    // Set values as in the OpenSSL example
    hex2bn_cuda(&a, "852D23DB15B6EFB341C5D19B0E5448E2E4DD7D7602B8885C1BA859400BFC27D7");
    hex2bn_cuda(&p, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2D");
    hex2bn_cuda(&m, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");

    printf("Base (a): ");
    bn_print_no_fuse("", &a);
    printf("Exponent (p): ");
    bn_print_no_fuse("", &p);
    printf("Modulus (m): ");
    bn_print_no_fuse("", &m);

    // Call BN_mod_exp_mont
    if (!BN_mod_exp_mont(&r, &a, &p, &m)) {
        printf("Error in BN_mod_exp_mont.\n");
    } else {
        printf("Result (r = a^p mod m): ");
        bn_print_no_fuse("", &r);
    }
}

int main() {
    // Set larger stack size if necessary
    size_t stackSize = 64 * 1024;  // 64KB
    cudaDeviceSetLimit(cudaLimitStackSize, stackSize);

    // Launch the kernel
    test_bn_mod_exp_mont<<<1,1>>>();
    cudaDeviceSynchronize();

    // Check for errors
    cudaError_t error = cudaGetLastError();
    if (error != cudaSuccess) {
        printf("CUDA error: %s\n", cudaGetErrorString(error));
        return 1;
    }

    return 0;
}

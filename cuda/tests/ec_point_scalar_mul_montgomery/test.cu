#include <stdio.h>
#include <cuda_runtime.h>
#include "bignum.h"
#include "montgomery.h"
#include "point.h"

__device__ void init_test_parameters(
    BIGNUM_CUDA *scalar,
    EC_POINT_JACOBIAN *point,
    MONT_CTX_CUDA *ctx
) {
    // Initialize scalar
    init_zero(scalar);
    scalar->d[3] = 0x1988f4633d8e6f31;
    scalar->d[2] = 0x2f3a8fc1da0e6274;
    scalar->d[1] = 0xf77940bb5ea3f36a;
    scalar->d[0] = 0x571cebc1db19b147;
    scalar->top = 4;
    scalar->neg = false;

    // Initialize point
    init_zero(&point->X);
    // 9981E643E9089F48979F48C033FD129C231E295329BC66DBD7362E5A487E2097
    point->X.d[3] = 0x9981E643E9089F48;
    point->X.d[2] = 0x979F48C033FD129C;
    point->X.d[1] = 0x231E295329BC66DB;
    point->X.d[0] = 0xD7362E5A487E2097;
    point->X.top = 4;
    point->X.neg = false;

    init_zero(&point->Y);
    // CF3F851FD4A582D670B6B59AAC19C1368DFC5D5D1F1DC64DB15EA6D2D3DBABE2
    point->Y.d[3] = 0xCF3F851FD4A582D6;
    point->Y.d[2] = 0x70B6B59AAC19C136;
    point->Y.d[1] = 0x8DFC5D5D1F1DC64D;
    point->Y.d[0] = 0xB15EA6D2D3DBABE2;
    point->Y.top = 4;
    point->Y.neg = false;

    init_zero(&point->Z);
    // 01000003D1
    point->Z.d[0] = 0x01000003D1;
    point->Z.top = 1;
    point->Z.neg = false;

    // Initialize Montgomery context
    init_zero(&ctx->R);
    ctx->R.d[4] = 0x1;
    ctx->R.top = 5;
    ctx->R.neg = false;

    init_zero(&ctx->n);
    ctx->n.d[3] = 0xFFFFFFFFFFFFFFFF;
    ctx->n.d[2] = 0xFFFFFFFFFFFFFFFF;
    ctx->n.d[1] = 0xFFFFFFFFFFFFFFFF;
    ctx->n.d[0] = 0xFFFFFFFEFFFFFC2F;
    ctx->n.top = 4;
    ctx->n.neg = false;

    init_zero(&ctx->n_prime);
    ctx->n_prime.d[3] = 0xc9bd1905155383999;
    ctx->n_prime.d[2] = 0xc46c2c295f2b761b;
    ctx->n_prime.d[1] = 0xcb223fedc24a059d;
    ctx->n_prime.d[0] = 0x838091dd2253531;
    ctx->n_prime.top = 4;
    ctx->n_prime.neg = false;

    init_zero(&ctx->R2);
    ctx->R2.d[1] = 0x1;
    ctx->R2.d[0] = 0x000007a2000e90a1;
    ctx->R2.top = 2;
    ctx->R2.neg = false;

    init_zero(&ctx->one);
    ctx->one.d[0] = 0x1000003d1;
    ctx->one.top = 1;
    ctx->one.neg = false;
}

__device__ void init_test_parameters_x(
    BIGNUM_CUDA *scalar,
    EC_POINT_CUDA *point,
    MONT_CTX_CUDA *ctx
) {
    // Initialize scalar
    init_zero(scalar);
    scalar->d[3] = 0x1988f4633d8e6f31;
    scalar->d[2] = 0x2f3a8fc1da0e6274;
    scalar->d[1] = 0xf77940bb5ea3f36a;
    scalar->d[0] = 0x571cebc1db19b147;
    scalar->top = 4;
    scalar->neg = false;

    // Initialize point
    init_zero(&point->x);
    point->x.d[3] = 0x79BE667EF9DCBBAC;
    point->x.d[2] = 0x55A06295CE870B07;
    point->x.d[1] = 0x029BFCDB2DCE28D9;
    point->x.d[0] = 0x59F2815B16F81798;
    point->x.top = 4;
    point->x.neg = false;

    init_zero(&point->y);
    point->y.d[3] = 0x483ADA7726A3C465;
    point->y.d[2] = 0x5DA4FBFC0E1108A8;
    point->y.d[1] = 0xFD17B448A6855419;
    point->y.d[0] = 0x9C47D08FFB10D4B8;
    point->y.top = 4;
    point->y.neg = false;

    // Initialize Montgomery context
    init_zero(&ctx->R);
    ctx->R.d[4] = 0x1;
    ctx->R.top = 5;
    ctx->R.neg = false;

    init_zero(&ctx->n);
    ctx->n.d[3] = 0xFFFFFFFFFFFFFFFF;
    ctx->n.d[2] = 0xFFFFFFFFFFFFFFFF;
    ctx->n.d[1] = 0xFFFFFFFFFFFFFFFF;
    ctx->n.d[0] = 0xFFFFFFFEFFFFFC2F;
    ctx->n.top = 4;
    ctx->n.neg = false;

    init_zero(&ctx->n_prime);
    ctx->n_prime.d[3] = 0xc9bd1905155383999;
    ctx->n_prime.d[2] = 0xc46c2c295f2b761b;
    ctx->n_prime.d[1] = 0xcb223fedc24a059d;
    ctx->n_prime.d[0] = 0x838091dd2253531;
    ctx->n_prime.top = 4;
    ctx->n_prime.neg = false;

    init_zero(&ctx->R2);
    ctx->R2.d[1] = 0x1;
    ctx->R2.d[0] = 0x000007a2000e90a1;
    ctx->R2.top = 2;
    ctx->R2.neg = false;

    init_zero(&ctx->one);
    ctx->one.d[0] = 0x1000003d1;
    ctx->one.top = 1;
    ctx->one.neg = false;
}

__global__ void test_kernel() {
    BIGNUM_CUDA scalar;
    EC_POINT_JACOBIAN point;
    MONT_CTX_CUDA ctx;
    EC_POINT_JACOBIAN result;

    // Initialize test parameters
    init_test_parameters(&scalar, &point, &ctx);

    // Call the function
    ec_point_scalar_mul_montgomery(&point, &scalar, &ctx, &result);
}

int main() {
    // Set larger stack size
    size_t stackSize = 64 * 1024;  // 64KB
    cudaDeviceSetLimit(cudaLimitStackSize, stackSize);

    // Launch kernel with a single thread
    test_kernel<<<1, 1>>>();
    
    // Wait for completion
    cudaDeviceSynchronize();

    // Check for errors
    cudaError_t error = cudaGetLastError();
    if (error != cudaSuccess) {
        printf("CUDA error: %s\n", cudaGetErrorString(error));
        return 1;
    }

    return 0;
}
#include <stdio.h>
#include <cuda_runtime.h>
#include "bignum.h"
#include "montgomery.h"
#include "point.h"

__device__ void init_test_vectors(
    EC_GROUP_CUDA *group,         // Curve parameters 
    EC_POINT_JACOBIAN *p_point        // base point
) {
    // Initialize secp256k1 curve parameters
    init_zero(&group->field);
    group->field.d[3] = 0xFFFFFFFFFFFFFFFF;
    group->field.d[2] = 0xFFFFFFFFFFFFFFFF;
    group->field.d[1] = 0xFFFFFFFFFFFFFFFF;
    group->field.d[0] = 0xFFFFFFFEFFFFFC2F;
    group->field.top = 4;
    group->field.neg = false;

    // a = 0
    init_zero(&group->a);
    group->a.top = 1;
    group->a.neg = false;

    // b = 7 
    init_zero(&group->b);
    group->b.d[0] = 7;
    group->b.top = 1;
    group->b.neg = false;

    // Initialize curve order
    init_zero(&group->order);
    group->order.d[3] = 0xFFFFFFFFFFFFFFFF;
    group->order.d[2] = 0xFFFFFFFFFFFFFFFE;
    group->order.d[1] = 0xBAAEDCE6AF48A03B;
    group->order.d[0] = 0xBFD25E8CD0364141;
    group->order.top = 4;
    group->order.neg = false;
    
    // Initialize base point P (secp256k1 generator) in affine coordinates
    init_zero(&p_point->X);
    p_point->X.d[3] = 0x79BE667EF9DCBBAC;
    p_point->X.d[2] = 0x55A06295CE870B07;
    p_point->X.d[1] = 0x029BFCDB2DCE28D9;  
    p_point->X.d[0] = 0x59F2815B16F81798;
    p_point->X.top = 4;
    p_point->X.neg = false;

    init_zero(&p_point->Y); 
    p_point->Y.d[3] = 0x483ADA7726A3C465;
    p_point->Y.d[2] = 0x5DA4FBFC0E1108A8;
    p_point->Y.d[1] = 0xFD17B448A6855419; 
    p_point->Y.d[0] = 0x9C47D08FFB10D4B8;
    p_point->Y.top = 4;
    p_point->Y.neg = false;

    // Initialize Z coordinate to 1
    init_zero(&p_point->Z);
    p_point->Z.d[0] = 1;
    p_point->Z.top = 1;
    p_point->Z.neg = false;
}

__global__ void test_ladder_pre() {
    printf("Test EC point ladder pre...\n");

    // Initialize test vectors
    EC_GROUP_CUDA group;
    EC_POINT_JACOBIAN p, r, s;

    // Initialize points
    init_jacobian_point(&r);
    init_jacobian_point(&s);

    // Setup test vectors
    init_test_vectors(&group, &p);

    printf("\nInitial state:\n"); 
    print_jacobian_point("P (base point)", &p);
    print_jacobian_point("R", &r);
    print_jacobian_point("S", &s);

    // Perform ladder pre step
    if (!ossl_ec_GFp_simple_ladder_pre(&group, &r, &s, &p)) {
        printf("Ladder pre operation failed!\n");
        return;
    }

    printf("\nAfter ladder pre:\n");
    print_jacobian_point("R", &r);
    print_jacobian_point("S", &s);
    print_jacobian_point("P (base point)", &p);
}

int main() {
    // Launch kernel 
    test_ladder_pre<<<1,1>>>();
    cudaDeviceSynchronize();

    // Check for errors
    cudaError_t error = cudaGetLastError();
    if (error != cudaSuccess) {
        printf("CUDA error: %s\n", cudaGetErrorString(error));
        return 1;
    }

    return 0;
}
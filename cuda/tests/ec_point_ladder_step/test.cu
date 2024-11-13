#include <cuda_runtime.h>
#include <stdio.h>
#include "bignum.h"
#include "montgomery.h"
#include "point.h"

__device__ void init_test_vectors(
    EC_GROUP_CUDA *group,         // Curve parameters  
    EC_POINT_CUDA *base_point,    // P in affine coordinates
    EC_POINT_CUDA *r_point,       // R in projective coordinates 
    EC_POINT_CUDA *s_point        // S in projective coordinates
) {
    // Initialize group parameters
    // Field prime
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
    
    // Initialize base point P (secp256k1 generator point)
    // x coordinate
    init_zero(&base_point->x);
    base_point->x.d[3] = 0x79BE667EF9DCBBAC;
    base_point->x.d[2] = 0x55A06295CE870B07;
    base_point->x.d[1] = 0x029BFCDB2DCE28D9;
    base_point->x.d[0] = 0x59F2815B16F81798;
    base_point->x.top = 4;
    base_point->x.neg = false;

    // y coordinate
    init_zero(&base_point->y);
    base_point->y.d[3] = 0x483ADA7726A3C465;
    base_point->y.d[2] = 0x5DA4FBFC0E1108A8;
    base_point->y.d[1] = 0xFD17B448A6855419;
    base_point->y.d[0] = 0x9C47D08FFB10D4B8;
    base_point->y.top = 4;
    base_point->y.neg = false;

    // Initialize R point (2P) in projective coordinates
    // x coordinate
    init_zero(&r_point->x);
    r_point->x.d[3] = 0xC6047F9441ED7D6D;
    r_point->x.d[2] = 0x3045406E95C07CD8;
    r_point->x.d[1] = 0x5C778E4B8CEF3CA7;
    r_point->x.d[0] = 0xABAC09B95C709EE5;
    r_point->x.top = 4;
    r_point->x.neg = false;

    // y coordinate 
    init_zero(&r_point->y);
    r_point->y.d[3] = 0x1AE168FEA63DC339;
    r_point->y.d[2] = 0xA3C58419466CEAEE;
    r_point->y.d[1] = 0xF7F632653266D0E1;
    r_point->y.d[0] = 0x236431A950CFE52A;
    r_point->y.top = 4;
    r_point->y.neg = false;

    // Initialize S point (P)
    bn_copy(&s_point->x, &base_point->x);
    bn_copy(&s_point->y, &base_point->y); 
}

__device__ void print_point(const char* label, const EC_POINT_CUDA *point) {
    printf("%s:\n", label);
    bn_print_no_fuse("  x: ", &point->x);
    bn_print_no_fuse("  y: ", &point->y);
}

__global__ void test_ladder_step() {
    printf("Starting ladder step test...\n");

    // Initialize test structures
    EC_GROUP_CUDA group;
    EC_POINT_CUDA base_point, r_point, s_point;
    
    // Initialize test vectors
    init_test_vectors(&group, &base_point, &r_point, &s_point);

    // Print initial values
    printf("Initial values:\n");
    print_point("Base point P", &base_point);
    print_point("R point (2P)", &r_point);
    print_point("S point (P)", &s_point);
    bn_print_no_fuse("Field prime", &group.field);
    bn_print_no_fuse("Curve a", &group.a);
    bn_print_no_fuse("Curve b", &group.b);
    bn_print_no_fuse("Group order", &group.order);

    // Perform ladder step
    int result = ec_point_ladder_step(&group, &r_point, &s_point, &base_point);
    
    if (result == 0) {
        printf("Ladder step operation failed!\n");
        return;
    }

    // Print results
    printf("\nResults after ladder step:\n");
    print_point("Result R point", &r_point);
    print_point("Result S point", &s_point);
}

int main() {
    // Set stack size
    size_t stackSize = 64 * 1024;  // 64KB
    cudaDeviceSetLimit(cudaLimitStackSize, stackSize);

    // Launch kernel
    test_ladder_step<<<1,1>>>();
    cudaDeviceSynchronize();

    // Check for errors
    cudaError_t error = cudaGetLastError();
    if (error != cudaSuccess) {
        printf("CUDA error: %s\n", cudaGetErrorString(error));
        return 1;
    }

    return 0;
}
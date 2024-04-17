#include <stdio.h>
#include <cuda_runtime.h>
#include "bignum.h"

__global__ void testKernel() {
    printf("++ testKernel for point_add ++\n");

    BIGNUM curveOrder;
    BN_ULONG curveOrder_d[4];

    // Initialize curveOrder_d
    // FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    curveOrder_d[0] = 0xFFFFFFFFFFFFFFFF;
    curveOrder_d[1] = 0xFFFFFFFFFFFFFFFE;
    curveOrder_d[2] = 0xBAAEDCE6AF48A03B;
    curveOrder_d[3] = 0xBFD25E8CD0364141;
    curveOrder.d = curveOrder_d;
    curveOrder.neg = 0;
    curveOrder.top = 4;

    // Initialize constants
    // CURVE_P is curveOrder_d
    CURVE_P.d = curveOrder_d;
    CURVE_P.top = 4;
    CURVE_P.neg = 0;
    
    for (int i = 0; i < 4; i++) CURVE_A_d[i] = 0;
    CURVE_A.d = CURVE_A_d;
    CURVE_A.top = 4;
    CURVE_A.neg = 0;

    BIGNUM *curve_prime = &CURVE_P;
    BIGNUM *curve_a = &CURVE_A;

    // Generator x coordinate
    // 79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
    CURVE_GX_d[0] = 0x79BE667EF9DCBBAC;
    CURVE_GX_d[1] = 0x55A06295CE870B07;
    CURVE_GX_d[2] = 0x029BFCDB2DCE28D9;
    CURVE_GX_d[3] = 0x59F2815B16F81798;

    // Generator y coordinate
    BIGNUM CURVE_GY;
    BN_ULONG CURVE_GY_d[4];
    // 483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
    CURVE_GY_d[0] = 0x483ADA7726A3C465;
    CURVE_GY_d[1] = 0x5DA4FBFC0E1108A8;
    CURVE_GY_d[2] = 0xFD17B448A6855419;
    CURVE_GY_d[3] = 0x9C47D08FFB10D4B8;

    // Initialize generator
    EC_POINT G;
    G.x.d = CURVE_GX_d; 
    G.y.d = CURVE_GY_d;
    // Set tops, negs
    G.x.top = 4;
    G.y.top = 4;
    G.x.neg = 0;
    G.y.neg = 0;
    
    EC_POINT result;                                 // Initialize the result variable, which accumulates the result
    init_point_at_infinity(&result);                 // Initialize it to the point at infinity

    // point_add(&result, &current, &result, curve_prime, curve_a);  // Add current to the result
    // Define p2
    BN_ULONG p2_xd[4];
    BN_ULONG p2_yd[4];
    // x: C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5
    p2_xd[0] = 0xC6047F9441ED7D6D;
    p2_xd[1] = 0x3045406E95C07CD8;
    p2_xd[2] = 0x5C778E4B8CEF3CA7;
    p2_xd[3] = 0xABAC09B95C709EE5;
    // y: 1AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A
    p2_yd[0] = 0x1AE168FEA63DC339;
    p2_yd[1] = 0xA3C58419466CEAEE;
    p2_yd[2] = 0xF7F632653266D0E1;
    p2_yd[3] = 0x236431A950CFE52A;
    EC_POINT p2;
    p2.x.d = p2_xd;
    p2.y.d = p2_yd;
    p2.x.top = 4;
    p2.y.top = 4;
    p2.x.neg = 0;
    p2.y.neg = 0;
    
    bn_print(">> G.x: ", &G.x);
    bn_print(">> G.y: ", &G.y);
    bn_print(">> p2.x: ", &p2.x);
    bn_print(">> p2.y: ", &p2.y);
    point_add(&result, &G, &p2, curve_prime, curve_a);  // Add current to the result
    bn_print("<< result.x: ", &result.x);
    bn_print("<< result.y: ", &result.y);

    printf("\n");
}

// Main function
int main() {
    testKernel<<<1, 1>>>();
    cudaError_t err = cudaGetLastError();
    if (err != cudaSuccess) {
        printf("Error: %s\n", cudaGetErrorString(err));
        return -1;
    }
    cudaDeviceSynchronize();
    return 0;
}
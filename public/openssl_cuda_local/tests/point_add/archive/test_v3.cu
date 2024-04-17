#include <stdio.h>
#include <cuda_runtime.h>
#include "bignum.h"

#define TEST_BIGNUM_WORDS 4

__global__ void testKernel() {
    printf("++ testKernel for point_add ++\n");
    // Addition
    BIGNUM a;
    BIGNUM b;
    BIGNUM curveOrder;
    BIGNUM newKey;

    BN_ULONG a_d[8];
    BN_ULONG b_d[8];
    BN_ULONG newKey_d[8];
    BN_ULONG curveOrder_d[16];

    // Initialize a
    // C17747B1566D9FE8AB7087E3F0C50175B788A1C84F4C756C405000A0CA2248E1
    a_d[0] = 0xC17747B1;
    a_d[1] = 0x566D9FE8;
    a_d[2] = 0xAB7087E3;
    a_d[3] = 0xF0C50175;
    a_d[4] = 0xB788A1C8;
    a_d[5] = 0x4F4C756C;
    a_d[6] = 0x405000A0;
    a_d[7] = 0xCA2248E1;  
    a.d = a_d; 
    a.top = 8;
    a.neg = 0;

    // Initialize b
    // 6C91CEA9CF0CAC55A7596D16B56D2AEFD204BB99DD677993158A7E6564F93CDF
    b_d[0] = 0x6C91CEA9;
    b_d[1] = 0xCF0CAC55;
    b_d[2] = 0xA7596D16;
    b_d[3] = 0xB56D2AEF;
    b_d[4] = 0xD204BB99;
    b_d[5] = 0xDD677993;
    b_d[6] = 0x158A7E65;
    b_d[7] = 0x64F93CDF;
    b.d = b_d;
    b.neg = 0;
    b.top = 8;

    // Initialize newKey_d
    for (int i = 0; i < 8; i++) newKey_d[i] = 0;
    newKey.d = newKey_d;
    newKey.neg = 0;
    newKey.top = 8;

    // Initialize curveOrder_d
    // FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    curveOrder_d[0] = 0xFFFFFFFF;
    curveOrder_d[1] = 0xFFFFFFFF;
    curveOrder_d[2] = 0xFFFFFFFF;
    curveOrder_d[3] = 0xFFFFFFFE;
    curveOrder_d[4] = 0xBAAEDCE6;
    curveOrder_d[5] = 0xAF48A03B;
    curveOrder_d[6] = 0xBFD25E8C;
    curveOrder_d[7] = 0xD0364141;
    curveOrder.d = curveOrder_d;
    curveOrder.neg = 0;
    curveOrder.top = 8;

    // Initialize constants
    // CURVE_P is curveOrder_d
    CURVE_P.d = curveOrder_d;
    CURVE_P.top = 8;
    CURVE_P.neg = 0;
    
    for (int i = 0; i < 8; i++) CURVE_A_d[i] = 0;
    CURVE_A.d = CURVE_A_d;
    CURVE_A.top = 8;
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
    
    // int num_tests = sizeof(test_values_a) / (sizeof(BN_ULONG) * TEST_BIGNUM_WORDS);
    // for (int test = 0; test < num_tests; ++test) {
        
    EC_POINT *point = &G;                            // Initialize the point with the generator
    EC_POINT current = *point;                       // This initializes the current point with the input point
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
    //}
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
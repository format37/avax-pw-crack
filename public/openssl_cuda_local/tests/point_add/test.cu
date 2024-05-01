#include <stdio.h>
#include <cuda_runtime.h>
#include "bignum.h"

#define TEST_BIGNUM_WORDS 4

__device__ void reverse_order(BN_ULONG test_values_a[][TEST_BIGNUM_WORDS], BN_ULONG test_values_b[][TEST_BIGNUM_WORDS], size_t num_rows) {
    for (size_t i = 0; i < num_rows; i++) {
        for (size_t j = 0; j < TEST_BIGNUM_WORDS / 2; j++) {
            BN_ULONG temp_a = test_values_a[i][j];
            test_values_a[i][j] = test_values_a[i][TEST_BIGNUM_WORDS - 1 - j];
            test_values_a[i][TEST_BIGNUM_WORDS - 1 - j] = temp_a;

            BN_ULONG temp_b = test_values_b[i][j];
            test_values_b[i][j] = test_values_b[i][TEST_BIGNUM_WORDS - 1 - j];
            test_values_b[i][TEST_BIGNUM_WORDS - 1 - j] = temp_b;
        }
    }
}

__device__ void reverse_order_single(BIGNUM *test_values_a) {
    for (size_t j = 0; j < TEST_BIGNUM_WORDS / 2; j++) {
        BN_ULONG temp_a = test_values_a->d[j];
        test_values_a->d[j] = test_values_a->d[TEST_BIGNUM_WORDS - 1 - j];
        test_values_a->d[TEST_BIGNUM_WORDS - 1 - j] = temp_a;
    }
}

__global__ void testKernel() {
    printf("++ testKernel for point_add ++\n");

    BIGNUM curveOrder;
    BN_ULONG curveOrder_d[4];
    BN_ULONG order_temp[4];

    // Initialize curveOrder_d
    // FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    // curveOrder_d[0] = 0xFFFFFFFFFFFFFFFF;
    // curveOrder_d[1] = 0xFFFFFFFFFFFFFFFF;
    // curveOrder_d[2] = 0xFFFFFFFFFFFFFFFF;
    // curveOrder_d[3] = 0xFFFFFFFEFFFFFC2F;
    // // Reverse order
    // reverse_order(&curveOrder_d, &order_temp, 1);
    // curveOrder.d = curveOrder_d;
    // curveOrder.neg = 0;
    // curveOrder.top = 4;

    // Initialize constants
    // CURVE_P is curveOrder_d
    // CURVE_P.d = curveOrder_d;
    // CURVE_P.top = 4;
    // CURVE_P.neg = 0;
    init_zero(&CURVE_P, MAX_BIGNUM_SIZE);
    // BN_ULONG CURVE_P_d[4];
    BN_ULONG CURVE_P_values[MAX_BIGNUM_SIZE] = {
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFEFFFFFC2F,
        0,0,0,0        
        };
    // for (int j = 0; j < MAX_BIGNUM_WORDS; ++j) {
    //         CURVE_P_d[j] = CURVE_P_values[j];
    //     }
    //CURVE_P.d = CURVE_P_d;
    CURVE_P.d = CURVE_P_values;
    CURVE_P.top = 4;
    CURVE_P.neg = 0;
    // reverse
    reverse_order_single(&CURVE_P);
    
    // for (int i = 0; i < 4; i++) CURVE_A_d[i] = 0;
    // CURVE_A.d = CURVE_A_d;
    // CURVE_A.top = 4;
    // CURVE_A.neg = 0;
    init_zero(&CURVE_A, MAX_BIGNUM_SIZE);

    BIGNUM *curve_prime = &CURVE_P;
    BIGNUM *curve_a = &CURVE_A;

    // Initialize generator
    BN_ULONG CURVE_GX_d[MAX_BIGNUM_SIZE];
    BN_ULONG CURVE_GY_d[MAX_BIGNUM_SIZE];


    // Generator x coordinate
    // 79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
    // CURVE_GX_d[0] = 0x79BE667EF9DCBBAC;
    // CURVE_GX_d[1] = 0x55A06295CE870B07;
    // CURVE_GX_d[2] = 0x029BFCDB2DCE28D9;
    // CURVE_GX_d[3] = 0x59F2815B16F81798;
    CURVE_GX_d[0] = 0xC6047F9441ED7D6D;
    CURVE_GX_d[1] = 0x3045406E95C07CD8;
    CURVE_GX_d[2] = 0x5C778E4B8CEF3CA7;
    CURVE_GX_d[3] = 0xABAC09B95C709EE5;
    for (int i = 4; i < MAX_BIGNUM_SIZE; i++) CURVE_GX_d[i] = 0;

    // Generator y coordinate
    BIGNUM CURVE_GY;
    //BN_ULONG CURVE_GY_d[4];
    // 483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
    // CURVE_GY_d[0] = 0x483ADA7726A3C465;
    // CURVE_GY_d[1] = 0x5DA4FBFC0E1108A8;
    // CURVE_GY_d[2] = 0xFD17B448A6855419;
    // CURVE_GY_d[3] = 0x9C47D08FFB10D4B8;
    CURVE_GY_d[0] = 0x1AE168FEA63DC339;
    CURVE_GY_d[1] = 0xA3C58419466CEAEE;
    CURVE_GY_d[2] = 0xF7F632653266D0E1;
    CURVE_GY_d[3] = 0x236431A950CFE52A;
    for (int i = 4; i < MAX_BIGNUM_SIZE; i++) CURVE_GY_d[i] = 0;

    // Reverse order
    //reverse_order(&CURVE_GX_d, &CURVE_GY_d, 1);

    // Initialize generator
    EC_POINT G;
    G.x.d = CURVE_GX_d; 
    G.y.d = CURVE_GY_d;
    // Set tops, negs
    G.x.top = 4;
    G.y.top = 4;
    G.x.neg = 0;
    G.y.neg = 0;

    reverse_order_single(&G.x);
    reverse_order_single(&G.y);
    
    EC_POINT result;                                 // Initialize the result variable, which accumulates the result
    init_point_at_infinity(&result);                 // Initialize it to the point at infinity

    // point_add(&result, &current, &result, curve_prime, curve_a);  // Add current to the result
    // Define p2
    BN_ULONG p2_xd[MAX_BIGNUM_SIZE];
    BN_ULONG p2_yd[MAX_BIGNUM_SIZE];
    // // x: C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5
    p2_xd[0] = 0xC6047F9441ED7D6D;
    p2_xd[1] = 0x3045406E95C07CD8;
    p2_xd[2] = 0x5C778E4B8CEF3CA7;
    p2_xd[3] = 0xABAC09B95C709EE5;
    // p2_xd[0] = 0x79BE667EF9DCBBAC;
    // p2_xd[1] = 0x55A06295CE870B07;
    // p2_xd[2] = 0x029BFCDB2DCE28D9;
    // p2_xd[3] = 0x59F2815B16F81798;
    for (int i = 4; i < MAX_BIGNUM_SIZE; i++) p2_xd[i] = 0;
    // // y: 1AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A
    p2_yd[0] = 0x1AE168FEA63DC339;
    p2_yd[1] = 0xA3C58419466CEAEE;
    p2_yd[2] = 0xF7F632653266D0E1;
    p2_yd[3] = 0x236431A950CFE52A;
    // p2_yd[0] = 0x483ADA7726A3C465;
    // p2_yd[1] = 0x5DA4FBFC0E1108A8;
    // p2_yd[2] = 0xFD17B448A6855419;
    // p2_yd[3] = 0x9C47D08FFB10D4B8;
    for (int i = 4; i < MAX_BIGNUM_SIZE; i++) p2_yd[i] = 0;
    // Reverse order
    // reverse_order(&p2_xd, &p2_yd, 1);
    EC_POINT p2;
    p2.x.d = p2_xd;
    p2.y.d = p2_yd;
    p2.x.top = 4;
    p2.y.top = 4;
    p2.x.neg = 0;
    p2.y.neg = 0;
    reverse_order_single(&p2.x);
    reverse_order_single(&p2.y);
    
    bn_print(">> G.x: ", &G.x);
    bn_print(">> G.y: ", &G.y);
    bn_print(">> p2.x: ", &p2.x);
    bn_print(">> p2.y: ", &p2.y);
    //return; // TODO: remove this line
    point_add(&result, &G, &p2, curve_prime, curve_a);  // point addition: p1.x != p2.x
    //point_add(&result, &G, &G, curve_prime, curve_a); // point doubling: p1.x == p2.x
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
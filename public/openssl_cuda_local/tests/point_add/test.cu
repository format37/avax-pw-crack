#include <stdio.h>
#include <cuda_runtime.h>
#include "bignum.h"
#include "ec_point.h"
#include "jacobian_point.h"

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
    clock_t start = clock64();
    BIGNUM curveOrder;
    BN_ULONG curveOrder_d[4];
    BN_ULONG order_temp[4];
    init_zero(&CURVE_P);
    // Init curve prime
    // fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
    BN_ULONG CURVE_P_values[MAX_BIGNUM_SIZE] = {
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFEFFFFFC2F,
        0,0,0,0        
        };
    for (int j = 0; j < MAX_BIGNUM_SIZE; ++j) {
            CURVE_P.d[j] = CURVE_P_values[j];
        }
    // reverse
    reverse_order(&CURVE_P, TEST_BIGNUM_WORDS);
    // find top
    CURVE_P.top = find_top(&CURVE_P);
    init_zero(&CURVE_A);

    BIGNUM *curve_prime = &CURVE_P;
    BIGNUM *curve_a = &CURVE_A;
    
    EC_POINT result;                                 // Initialize the result variable, which accumulates the result
    init_point_at_infinity(&result);                 // Initialize it to the point at infinity

    // Initialize p1
    EC_POINT p1;
    init_zero(&p1.x);
    init_zero(&p1.y);
    // Fill p1.x as 79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
    p1.x.d[0] = 0x79be667ef9dcbbac;
    p1.x.d[1] = 0x55a06295ce870b07;
    p1.x.d[2] = 0x029bfcdb2dce28d9;
    p1.x.d[3] = 0x59f2815b16f81798;
    // Fill p1.y as 483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
    p1.y.d[0] = 0x483ada7726a3c465;
    p1.y.d[1] = 0x5da4fbfc0e1108a8;
    p1.y.d[2] = 0xfd17b448a6855419;
    p1.y.d[3] = 0x9c47d08ffb10d4b8;
    // Reverse order
    reverse_order_single(&p1.x);
    reverse_order_single(&p1.y);
    // Find top
    p1.x.top = find_top(&p1.x);
    p1.y.top = find_top(&p1.y);    

    // Initialize p2
    EC_POINT p2;
    init_zero(&p2.x);
    init_zero(&p2.y);
    // Fill p2.x as c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5
    p2.x.d[0] = 0xc6047f9441ed7d6d;
    p2.x.d[1] = 0x3045406e95c07cd8;
    p2.x.d[2] = 0x5c778e4b8cef3ca7;
    p2.x.d[3] = 0xabac09b95c709ee5;
    // Fill p2.y as 1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a
    p2.y.d[0] = 0x1ae168fea63dc339;
    p2.y.d[1] = 0xa3c58419466ceaee;
    p2.y.d[2] = 0xf7f632653266d0e1;
    p2.y.d[3] = 0x236431a950cfe52a;
    // Reverse order
    reverse_order(&p2.x, TEST_BIGNUM_WORDS);
    reverse_order(&p2.y, TEST_BIGNUM_WORDS);
    // Find top
    p2.x.top = find_top(&p2.x);
    p2.y.top = find_top(&p2.y);
    
    bn_print(">> p1.x: ", &p1.x);
    bn_print(">> p1.y: ", &p1.y);
    bn_print(">> p2.x: ", &p2.x);
    bn_print(">> p2.y: ", &p2.y);
    
    if (0) point_add(&result, &p1, &p2, curve_prime, curve_a);  // point addition: p1.x != p2.x
    else {
        // Convert affine points to Jacobian coordinates
        JacobianPoint jac_p1, jac_p2, jac_result;
        affine_to_jacobian(&jac_p1, &p1);
        affine_to_jacobian(&jac_p2, &p2);
        // Perform Jacobian point addition
        jacobian_point_add(&jac_result, &jac_p1, &jac_p2, &CURVE_P);
        // Convert result back to affine coordinates
        // EC_POINT result;
        jacobian_to_affine(&result, &jac_result, &CURVE_P);
    }

    bn_print("<< result.x: ", &result.x);
    bn_print("<< result.y: ", &result.y);

    printf("\n");
    record_function(FN_MAIN, start);
    print_performance_report();
}

// Main function
int main() {
    for (int i = 0; i < 1; i++) {
        testKernel<<<1, 1>>>();
        cudaError_t err = cudaGetLastError();
        if (err != cudaSuccess) {
            printf("Error: %s\n", cudaGetErrorString(err));
            return -1;
        }
        cudaDeviceSynchronize();
    }
    // testKernel<<<1, 1>>>();
    // cudaError_t err = cudaGetLastError();
    // if (err != cudaSuccess) {
    //     printf("Error: %s\n", cudaGetErrorString(err));
    //     return -1;
    // }
    // cudaDeviceSynchronize();
    return 0;
}
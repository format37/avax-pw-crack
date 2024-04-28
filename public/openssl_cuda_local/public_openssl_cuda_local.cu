#include <stdio.h>
#include <cuda.h>
#include "bignum.h"

#define TEST_BIGNUM_WORDS 4

__device__ void reverse_order(BIGNUM *test_values_a) {
    for (size_t j = 0; j < TEST_BIGNUM_WORDS / 2; j++) {
        BN_ULONG temp_a = test_values_a->d[j];
        test_values_a->d[j] = test_values_a->d[TEST_BIGNUM_WORDS - 1 - j];
        test_values_a->d[TEST_BIGNUM_WORDS - 1 - j] = temp_a;
    }
}

//__device__ EC_POINT ec_point_scalar_mul(EC_POINT *point, BIGNUM *scalar, BIGNUM *curve_order) {
__device__ EC_POINT ec_point_scalar_mul(
    EC_POINT *point, 
    BIGNUM *scalar, 
    BIGNUM *curve_prime, 
    BIGNUM *curve_a
    ) {
    printf("++ ec_point_scalar_mul ++\n");
    // Print point
    bn_print(">> point x: ", &point->x);
    bn_print(">> point y: ", &point->y);
    bn_print(">> scalar: ", scalar);
    bn_print(">> curve_prime: ", curve_prime);
    bn_print(">> curve_a: ", curve_a);    

    EC_POINT current = *point;                       // This initializes the current point with the input point
    EC_POINT result;                                 // Initialize the result variable, which accumulates the result

    init_point_at_infinity(&result);                 // Initialize it to the point at infinity

    // Convert scalar BIGNUM to an array of integers that's easy to iterate bit-wise
    unsigned int bits[256];                          // Assuming a 256-bit scalar
    bignum_to_bit_array(scalar, bits);               // You will need to implement bignum_to_bit_array()
    
    // debug_printf("coef hex: %s\n", bignum_to_hex(scalar)); // Convert BIGNUM to hex string for printing
    bn_print("coef: ", scalar);  
    
    int debug_counter = 1;
    
    for (int i = 0; i < 256; i++) {                 // Assuming 256-bit scalars
        if (i<debug_counter) {
            // debug_printf("0 x: %s\n", bignum_to_hex(&current.x));
            bn_print("0 current.x: ", &current.x);
            // debug_printf("0 y: %s\n", bignum_to_hex(&current.y));
            bn_print("0 current.y: ", &current.y);
        }
        

        if (bits[i]) {// If the i-th bit is set
            printf("0: Interrupting for debug\n");
            return result; // TODO: remove this
            // if (i<debug_counter) printf("# 0\n");
            // point_add(&result, &current, &result);  // Add current to the result
            // point_add(&result, &current, &result, &field_order);  // Add current to the result
            //point_add(&result, &current, &result, curve_order);  // Add current to the result
            

            point_add(&result, &current, &result, curve_prime, curve_a);  // Add current to the result
            
            

             // if (i<debug_counter) printf("# b\n");
            // debug_printf("1 x: %s\n", bignum_to_hex(&result.x));
             if (i<debug_counter) bn_print("1 result.x: ", &result.x);
            // debug_printf("1 y: %s\n", bignum_to_hex(&result.y));
             if (i<debug_counter) bn_print("1 result.y: ", &result.y);

        }
        else {
            printf("1: Interrupting for debug\n");
            return result; // TODO: remove this
        }
        if (i<debug_counter) debug_printf("# c\n");

        //point_double(&current, &current);           // Double current
        // point_double(&current, &current, &field_order);  // Double current and store the result in current
        // point_double(&current, &current, curve_order);

        // We don't need to double the point. We can just add it to itself.
        //point_add(&current, &current, &current, curve_order);
        point_add(&current, &current, &current, curve_prime, curve_a);  // Double current by adding to itself

        // debug_printf("2 x: %s\n", bignum_to_hex(&current.x));
        if (i<debug_counter) bn_print("2 current.x: ", &current.x);
        // debug_printf("2 y: %s\n", bignum_to_hex(&current.y));
        if (i<debug_counter) bn_print("2 current.y: ", &current.y);
        //printf("BREAKING\n");
        // break; // TODO: remove this
    }

    // debug_printf("Final x: %s\n", bignum_to_hex(&result.x));
    bn_print("Final x: ", &result.x);
    // debug_printf("Final y: %s\n", bignum_to_hex(&result.y));
    bn_print("Final y: ", &result.y);
    printf("-- ec_point_scalar_mul --\n");
    return result;
}
// Public key derivation --

__global__ void testKernel() {

    // BN_CTX *ctx = BN_CTX_new();

    // return;

    // Addition
    BIGNUM a;
    BIGNUM b;
    BIGNUM curveOrder;
    BIGNUM newKey;

    init_zero(&a, MAX_BIGNUM_SIZE);
    init_zero(&b, MAX_BIGNUM_SIZE);
    init_zero(&curveOrder, MAX_BIGNUM_SIZE);
    init_zero(&newKey, MAX_BIGNUM_SIZE);

    BN_ULONG a_d[4];
    BN_ULONG b_d[4];
    //BN_ULONG curveOrder_d[4];

    // Initialize a
    // C17747B1566D9FE8AB7087E3F0C50175B788A1C84F4C756C405000A0CA2248E1
    a_d[0] = 0xC17747B1566D9FE8;
    a_d[1] = 0xAB7087E3F0C50175;
    a_d[2] = 0xB788A1C84F4C756C;
    a_d[3] = 0x405000A0CA2248E1; 
    a.d = a_d; 
    a.top = 4;
    a.neg = 0;

    // Initialize b
    // 6C91CEA9CF0CAC55A7596D16B56D2AEFD204BB99DD677993158A7E6564F93CDF
    b_d[0] = 0x6C91CEA9CF0CAC55;
    b_d[1] = 0xA7596D16B56D2AEF;
    b_d[2] = 0xD204BB99DD677993;
    b_d[3] = 0x158A7E6564F93CDF;
    b.d = b_d;
    b.top = 4;
    b.neg = 0;

    BN_ULONG curveOrder_values[MAX_BIGNUM_WORDS] = {
        0xffffffffffffffff,
        0xFFFFFFFFFFFFFFFE,
        0xBAAEDCE6AF48A03B,
        0xBFD25E8CD0364141
        };

    for (int j = 0; j < TEST_BIGNUM_WORDS; ++j) {
            curveOrder.d[j] = curveOrder_values[j];
        }

    // Initialize curveOrder_d
    // FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    // curveOrder_d[0] = 0xFFFFFFFFFFFFFFFF;
    // curveOrder_d[1] = 0xFFFFFFFFFFFFFFFE;
    // curveOrder_d[2] = 0xBAAEDCE6AF48A03B;
    // curveOrder_d[3] = 0xBFD25E8CD0364141;
    // curveOrder.d = curveOrder_d;
    // curveOrder.neg = 0;
    // curveOrder.top = 4;

    reverse_order(&a);
    reverse_order(&b);
    reverse_order(&curveOrder);

    // Print inputs
    // bn_print(">> bn_add a: ", &a);
    // bn_print(">> bn_add b: ", &b);

    // Add A and B
    //bn_print(">> bn_add newKey: ", &newKey);
    bn_add(&newKey, &a, &b); // result = a + b
    // bn_print("<< bn_add newKey: ", &newKey);

    // Modular Reduction
    BIGNUM m;
    BN_ULONG m_d[4];
    for (int i = 0; i < 4; i++) m_d[i] = 0;
    m_d[0] = 0x64; // 100
    m.d = m_d;
    m.top = 1;
    m.neg = 0;
    
    BIGNUM tmp;
    init_zero(&tmp, MAX_BIGNUM_SIZE);
    bn_copy(&tmp, &newKey);
    // bn_print("\n>> bn_mod tmp: ", &tmp);
    // bn_print(">> curveOrder: ", &curveOrder);
    bn_mod(&newKey, &tmp, &curveOrder); // a = b mod c
    // bn_print("<< bn_mod newKey: ", &newKey);
    // printf("(expected): 2E09165B257A4C3E52C9F4FAA6322C66CEDE807B7D6B4EC3960820795EE5447F\n");
    bn_print("\Private key: ", &newKey);

    // Derive the public key
    printf("\nDeriving the public key..\n");
    // Initialize constants
    // CURVE_P is curveOrder_d
    // CURVE_P.d = curveOrder_d;
    // CURVE_P.top = 4;
    // CURVE_P.neg = 0;
    
    // for (int i = 0; i < 4; i++) CURVE_A_d[i] = 0;
    // CURVE_A.d = CURVE_A_d;
    // CURVE_A.top = 4;
    // CURVE_A.neg = 0;
    init_zero(&CURVE_A, MAX_BIGNUM_SIZE);
    
    // For secp256k1, CURVE_B should be initialized to 7 rather than 0
    for (int i = 0; i < 4; i++) CURVE_B_d[i] = 0;
    CURVE_B_d[0] = 0x7;
    CURVE_B.d = CURVE_B_d;
    CURVE_B.top = 4;
    CURVE_B.neg = 0;

    // Generator x coordinate
    CURVE_GX_d[0] = 0x79BE667EF9DCBBAC;
    CURVE_GX_d[1] = 0x55A06295CE870B07;
    CURVE_GX_d[2] = 0x029BFCDB2DCE28D9;
    CURVE_GX_d[3] = 0x59F2815B16F81798; 

    // Generator y coordinate
    BIGNUM CURVE_GY;
    BN_ULONG CURVE_GY_d[4];
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

    // Derive public key 
    // EC_POINT publicKey = ec_point_scalar_mul(&G, &newKey, &curveOrder);    
    
    bn_copy(&CURVE_P, &curveOrder);

    EC_POINT publicKey = ec_point_scalar_mul(&G, &newKey, &CURVE_P, &CURVE_A);
    
    
    // ec_point_scalar_mul / point_add / mod_mul / bn_mod <= Issue

    // Print public key
    printf("Public key:\n");
    bn_print("Public key x: ", &publicKey.x);
    bn_print("Public key y: ", &publicKey.y);


    // BN_CTX_free(ctx);

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
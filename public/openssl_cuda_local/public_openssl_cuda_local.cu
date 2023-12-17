#include <stdio.h>
#include <cuda.h>
#include "bignum.h"

//__device__ EC_POINT ec_point_scalar_mul(EC_POINT *point, BIGNUM *scalar, BIGNUM *curve_order) {
__device__ EC_POINT ec_point_scalar_mul(
    EC_POINT *point, 
    BIGNUM *scalar, 
    BIGNUM *curve_prime, 
    BIGNUM *curve_a
    ) {
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
        break; // TODO: remove this
    }

    // debug_printf("Final x: %s\n", bignum_to_hex(&result.x));
    bn_print("Final x: ", &result.x);
    // debug_printf("Final y: %s\n", bignum_to_hex(&result.y));
    bn_print("Final y: ", &result.y);

    return result;
}
// Public key derivation --

__global__ void testKernel() {

    // BN_CTX *ctx = BN_CTX_new();

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

    // Print inputs
    bn_print("A: ", &a);
    bn_print("B: ", &b);

    // Add A and B
    bn_add(&a, &b, &newKey);
    
    // Print A + B
    bn_print("Debug Cuda newKey (After add): ", &newKey);

    // Modular Reduction
    BIGNUM m;
    BN_ULONG m_d[8];
    for (int i = 0; i < 8; i++) m_d[i] = 0;
    m_d[0] = 0x00000064; // 100
    m.d = m_d;
    m.top = 1;
    m.neg = 0;
    
    printf("Calling bn_nnmod\n");
    bn_mod(&newKey, &newKey, &curveOrder);

    printf("Debug Cuda newKey (expected_): 2E09165B257A4C3E52C9F4FAA6322C66CEDE807B7D6B4EC3960820795EE5447F\n");
    bn_print("Debug Cuda newKey (After mod): ", &newKey);


    // Derive the public key
    printf("Deriving the public key..\n");
    // Initialize constants
    // CURVE_P is curveOrder_d
    CURVE_P.d = curveOrder_d;
    CURVE_P.top = 8;
    CURVE_P.neg = 0;
    
    for (int i = 0; i < 8; i++) CURVE_A_d[i] = 0;
    CURVE_A.d = CURVE_A_d;
    CURVE_A.top = 8;
    CURVE_A.neg = 0;
    
    // For secp256k1, CURVE_B should be initialized to 7 rather than 0
    for (int i = 0; i < 8; i++) CURVE_B_d[i] = 0;
    CURVE_B_d[0] = 0x00000007;
    CURVE_B.d = CURVE_B_d;
    CURVE_B.top = 8;
    CURVE_B.neg = 0;

    // Generator x coordinate
    CURVE_GX_d[0] = 0x79BE667E;
    CURVE_GX_d[1] = 0xF9DCBBAC;
    CURVE_GX_d[2] = 0x55A06295;
    CURVE_GX_d[3] = 0xCE870B07;
    CURVE_GX_d[4] = 0x029BFCDB;
    CURVE_GX_d[5] = 0x2DCE28D9;
    CURVE_GX_d[6] = 0x59F2815B;
    CURVE_GX_d[7] = 0x16F81798; 

    // Generator y coordinate
    BIGNUM CURVE_GY;
    BN_ULONG CURVE_GY_d[8];
    CURVE_GY_d[0] = 0x483ADA77;
    CURVE_GY_d[1] = 0x26A3C465;
    CURVE_GY_d[2] = 0x5DA4FBFC;
    CURVE_GY_d[3] = 0x0E1108A8;
    CURVE_GY_d[4] = 0xFD17B448;
    CURVE_GY_d[5] = 0xA6855419;
    CURVE_GY_d[6] = 0x9C47D08F;
    CURVE_GY_d[7] = 0xFB10D4B8;

    // Initialize generator
    EC_POINT G;
    G.x.d = CURVE_GX_d; 
    G.y.d = CURVE_GY_d;
    // Set tops, negs
    G.x.top = 8;
    G.y.top = 8;
    G.x.neg = 0;
    G.y.neg = 0;

    // Derive public key 
    // EC_POINT publicKey = ec_point_scalar_mul(&G, &newKey, &curveOrder);
    EC_POINT publicKey = ec_point_scalar_mul(&G, &newKey, &CURVE_P, &CURVE_A);
    // ec_point_scalar_mul / point_add / mod_mul / bn_mod <= Issue

    // Print public key
    printf("Public key:\n");
    bn_print("Public key x: ", &publicKey.x);
    bn_print("Public key y: ", &publicKey.y);


    // BN_CTX_free(ctx);

}

int main() {
    // print that we starting
    printf("Starting\n");
    testKernel<<<1,1>>>();
    cudaError_t err = cudaGetLastError();
    if (err != cudaSuccess) {
        printf("Error: %s\n", cudaGetErrorString(err));
        return -1;
    }
    cudaDeviceSynchronize();
    return 0;
}
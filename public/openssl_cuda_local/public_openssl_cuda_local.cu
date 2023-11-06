#include <stdio.h>
#include <cuda.h>
#include "bignum.h"

__device__ int simple_BN_nnmod(BIGNUM *r, const BIGNUM *m, const BIGNUM *d)
{
    // Check for division by zero
    if (d->top == 0) {
        return 0; // Error code
    }

    // Perform the modulo operation; this is a simplified operation assuming single-precision
    BN_ULONG remainder = m->d[0] % d->d[0];

    // Check the sign and adjust if necessary
    if (m->neg) {
        remainder = d->d[0] - remainder;
    }

    // Update the result BIGNUM
    r->d[0] = remainder;
    r->top = 1; // Simplified; assuming single-precision arithmetic
    r->neg = 0; // Result is always non-negative

    return 1; // Success
}

__device__ void big_num_add_mod(BN_ULONG *result, BN_ULONG *a, BN_ULONG *b, BN_ULONG *n, int num_words) {
    BN_ULONG carry = 0;
    for (int i = num_words - 1; i >= 0; i--) {
        unsigned long long sum = (unsigned long long) a[i] + (unsigned long long) b[i] + carry; // Use 64-bit to prevent overflow
        result[i] = (BN_ULONG) (sum % 0x100000000);  // Keep lower 32 bits
        carry = (BN_ULONG) (sum >> 32); // Upper 32 bits become carry
    }

    // Modular reduction: simply subtract n from result if result >= n
    for (int i = 0; i < num_words; i++) {
        if (result[i] < n[i]) return; // Early exit if we find a smaller component
        if (result[i] > n[i]) break; // Continue if we find a larger component
    }
    // At this point, we know result >= n, so perform result -= n
    carry = 0;
    for (int i = num_words - 1; i >= 0; i--) {
        long long diff = (long long) result[i] - (long long) n[i] - carry; // Use 64-bit to prevent underflow
        if (diff < 0) {
            diff += 0x100000000; // Borrow from next word
            carry = 1;
        } else {
            carry = 0;
        }
        result[i] = (BN_ULONG) diff;
    }
}

__device__ void robust_BN_nnmod(BIGNUM *r, const BIGNUM *m, const BIGNUM *d) {
    // Copy m into r
    for (int i = 0; i < m->top; ++i) {
        r->d[i] = m->d[i];
    }
    r->top = m->top;
    r->neg = 0;  // Result is non-negative

    // Now we'll reduce r modulo d, using simple division
    for (int i = 0; i < r->top; ++i) {
        if (r->d[i] >= d->d[0]) {
            BN_ULONG quotient = r->d[i] / d->d[0];
            BN_ULONG remainder = r->d[i] % d->d[0];

            // Subtract quotient*d from r
            BN_ULONG borrow = 0;
            for (int j = 0; j < d->top; ++j) {
                unsigned long long sub = (unsigned long long) r->d[i+j] - (unsigned long long) d->d[j] * quotient - borrow;
                r->d[i+j] = (BN_ULONG) (sub % 0x100000000);
                borrow = (BN_ULONG) (sub >> 32);
            }

            // Add back the remainder at position i
            unsigned long long sum = (unsigned long long) r->d[i] + (unsigned long long) remainder;
            r->d[i] = (BN_ULONG) (sum % 0x100000000);
            BN_ULONG carry = (BN_ULONG) (sum >> 32);

            // Propagate any carry
            for (int j = i+1; j < r->top && carry; ++j) {
                sum = (unsigned long long) r->d[j] + carry;
                r->d[j] = (BN_ULONG) (sum % 0x100000000);
                carry = (BN_ULONG) (sum >> 32);
            }

            // If there's still a carry, increase the size of r
            if (carry) {
                r->d[r->top] = carry;
                r->top++;
            }
        }
    }
}

// Public key derivation ++
__device__ BIGNUM CURVE_P;
__device__ BIGNUM CURVE_A;
__device__ BIGNUM CURVE_B;
__device__ BIGNUM CURVE_GX;
__device__ BIGNUM CURVE_GY;
__device__ BN_ULONG CURVE_P_d[8];
__device__ BN_ULONG CURVE_A_d[8];
__device__ BN_ULONG CURVE_B_d[8];
__device__ BN_ULONG CURVE_GX_d[8];
__device__ BN_ULONG CURVE_GY_d[8];

struct EC_POINT {
  BIGNUM x; 
  BIGNUM y;
};

__device__ EC_POINT point_add(EC_POINT P1, EC_POINT P2) {
  
  // Point addition formula using existing BIGNUM ops
  
  EC_POINT sum;
  
  // x3 = x1 + x2 
  bn_add(&P1.x, &P2.x, &sum.x); 
  
  // y3 = y1 + y2
  bn_add(&P1.y, &P2.y, &sum.y);
  
  // Reduce coordinates modulo p (curve order)
  bn_mod(&sum.x, &CURVE_P, &CURVE_P);
  bn_mod(&sum.y, &CURVE_P, &CURVE_P);

  return sum;
}
// Public key derivation --

__global__ void testKernel() {

    BN_CTX *ctx = BN_CTX_new();

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
    // expected:2E09165B257A4C3E52C9F4FAA6322C66CEDE807B7D6B4EC3960820795EE5447F

    /*if (!simple_BN_nnmod(&newKey, &newKey, &curveOrder)) {
        // Handle error (e.g., division by zero)
        printf("Error: Division by zero\n");
    }*/
    
    //big_num_add_mod(newKey.d, a.d, b.d, curveOrder.d, a.top); // Fine:2e09165b257a4c3e52c9f4faa6322c6 Wrong:5898d5d622cb3eeff55da7f062f1b85c0

    //robust_BN_nnmod(&newKey, &newKey, &curveOrder); // Wrong:5c122cb6257a4c3e52c9f4faa6322c66cede807b7d6b4ec4960820795ee54480
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
    CURVE_GX.d = CURVE_GX_d;
    CURVE_GX.top = 8;
    CURVE_GX.neg = 0;   

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
    CURVE_GY.d = CURVE_GY_d;
    CURVE_GY.top = 8;
    CURVE_GY.neg = 0;

    BN_CTX_free(ctx);

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
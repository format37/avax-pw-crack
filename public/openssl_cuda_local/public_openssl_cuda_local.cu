#include <fstream>
#include <iomanip>
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

__device__ EC_POINT ec_point_scalar_mul(
    EC_POINT *point, 
    BIGNUM *scalar, 
    BIGNUM *curve_prime, 
    BIGNUM *curve_a
    ) {
    // debug_printf("++ ec_point_scalar_mul ++\n");
    // Print point
    bn_print(">> point x: ", &point->x);
    bn_print(">> point y: ", &point->y);
    bn_print(">> scalar: ", scalar);
    bn_print(">> curve_prime: ", curve_prime);
    bn_print(">> curve_a: ", curve_a);    
    
    EC_POINT current = *point; // This initializes the current point with the input point
    EC_POINT result; // Initialize the result variable, which accumulates the result
    EC_POINT tmp_result;
    EC_POINT tmp_a;
    EC_POINT tmp_b;                                     
    
    init_point_at_infinity(&result);                 // Initialize it to the point at infinity
    init_point_at_infinity(&tmp_result);                 // Initialize it to the point at infinity
    init_point_at_infinity(&tmp_a);                 // Initialize it to the point at infinity
    init_point_at_infinity(&tmp_b);                 // Initialize it to the point at infinity
    // printf("0: Interrupting for debug\n");
    
    // Convert scalar BIGNUM to an array of integers that's easy to iterate bit-wise
    unsigned int bits[256];                          // Assuming a 256-bit scalar
    bignum_to_bit_array(scalar, bits);               // You will need to implement bignum_to_bit_array()
    
    // printf("coef hex: %s\n", bignum_to_hex(scalar)); // Convert BIGNUM to hex string for printing
    bn_print("coef: ", scalar);  
    
    // int debug_counter = 1;    
    
    for (int i = 0; i < 256; i++) {                 // Assuming 256-bit scalars
        // printf("\n### Step: %d\n", i);
        // if (i<debug_counter) {
        //     // printf("0 x: %s\n", bignum_to_hex(&current.x));
        //     bn_print("0 current.x: ", &current.x);
        //     // printf("0 y: %s\n", bignum_to_hex(&current.y));
        //     bn_print("0 current.y: ", &current.y);
        // }
        

        if (bits[i]) {// If the i-th bit is set
            // printf("\n[0]\n");
            // printf("0: Interrupting for debug\n");
            // return result; // TODO: remove this
            // if (i<debug_counter) printf("# 0\n");
            // point_add(&result, &current, &result);  // Add current to the result
            // point_add(&result, &current, &result, &field_order);  // Add current to the result
            //point_add(&result, &current, &result, curve_order);  // Add current to the result

            // init tmp_result
            init_point_at_infinity(&tmp_result); 
            
            bn_print(">> point_add result.x: ", &result.x);
            bn_print(">> point_add result.y: ", &result.y);
            bn_print(">> point_add current.x: ", &current.x);
            bn_print(">> point_add current.y: ", &current.y);
            bn_print(">> curve_prime: ", curve_prime);
            bn_print(">> curve_a: ", curve_a);
            point_add(&tmp_result, &result, &current, curve_prime, curve_a);  // Add current to the result
            init_point_at_infinity(&result); // Reset result
            bn_copy(&result.x, &tmp_result.x);
            bn_copy(&result.y, &tmp_result.y);
            bn_print("<< point_add result.x: ", &result.x);
            bn_print("<< point_add result.y: ", &result.y);
            
            // if (i<debug_counter) printf("# b\n");
            // printf("1 x: %s\n", bignum_to_hex(&result.x));
            //  if (i<debug_counter) bn_print("1 result.x: ", &result.x);
            // printf("1 y: %s\n", bignum_to_hex(&result.y));
            //  if (i<debug_counter) bn_print("1 result.y: ", &result.y);
            // printf("\n");
            
        }
        // else {
        //     printf("1: Interrupting for debug\n");
        //     return result; // TODO: remove this
        // }
        // if (i<debug_counter) printf("# c\n");

        //point_double(&current, &current);           // Double current
        // point_double(&current, &current, &field_order);  // Double current and store the result in current
        // point_double(&current, &current, curve_order);

        // We don't need to double the point. We can just add it to itself.
        //point_add(&current, &current, &current, curve_order);
        // bn_print("\n>> [1] point_add current.x: ", &current.x);
        // bn_print(">> point_add current.y: ", &current.y);
        // bn_print(">> point_add result.x: ", &result.x);
        // bn_print(">> point_add result.y: ", &result.y);
        // bn_print(">> point_add curve_prime: ", curve_prime);
        // bn_print(">> point_add curve_a: ", curve_a);
        // printf("0: Interrupting for debug\n");
        // return result; // TODO: remove this
        // __device__ int point_add(
        //     EC_POINT *result, 
        //     EC_POINT *p1, 
        //     EC_POINT *p2, 
        //     BIGNUM *p, 
        //     BIGNUM *a
        // ) {
        // init tmp_result
        init_point_at_infinity(&tmp_result);
        // init tmp_a
        init_point_at_infinity(&tmp_a);
        // init tmp_b
        init_point_at_infinity(&tmp_b);
        // Copy current to tmp_a
        bn_copy(&tmp_a.x, &current.x);
        bn_copy(&tmp_a.y, &current.y);
        // Copy current to tmp_b
        bn_copy(&tmp_b.x, &current.x);
        bn_copy(&tmp_b.y, &current.y);

        // printf("\n[1]\n");
        bn_print(">> point_add tmp_a.x: ", &tmp_a.x);
        bn_print(">> point_add tmp_a.y: ", &tmp_a.y);
        bn_print(">> point_add tmp_b.x: ", &tmp_b.x);
        bn_print(">> point_add tmp_b.y: ", &tmp_b.y);
        bn_print(">> point_add tmp_result.x: ", &tmp_result.x);
        bn_print(">> point_add tmp_result.y: ", &tmp_result.y);
        // print curve_prime and curve_a
        bn_print(">> point_add curve_prime: ", curve_prime);
        bn_print(">> point_add curve_a: ", curve_a);

        

        point_add(&tmp_result, &tmp_a, &tmp_b, curve_prime, curve_a);  // Double current by adding to itself
        // ATTENTION: tmp_result is not related to result

        // printf("### Breaking at i: %d\n", i);
        // break; // TODO: remove this

        bn_print("\n<< point_add tmp_result.x (pp.x): ", &tmp_result.x);
        bn_print("<< point_add tmp_result.y (pp.y): ", &tmp_result.y);
        bn_print("<< point_add tmp_a.x (p1.x): ", &tmp_a.x);
        bn_print("<< point_add tmp_a.y (p1.y): ", &tmp_a.y);
        bn_print("<< point_add tmp_b.x (p2.x): ", &tmp_b.x);
        bn_print("<< point_add tmp_b.y (p2.y):", &tmp_b.y);
        bn_print("<< point_add curve_prime: ", curve_prime);
        bn_print("<< point_add curve_a: ", curve_a);

        // Copy tmp_result to current
        bn_copy(&current.x, &tmp_result.x);
        bn_copy(&current.y, &tmp_result.y);
        bn_print("\n<< point_add current.x: ", &current.x);
        bn_print("<< point_add current.y: ", &current.y);

        // printf("2 x: %s\n", bignum_to_hex(&current.x));
        // if (i<debug_counter) bn_print("2 current.x: ", &current.x);
        // printf("2 y: %s\n", bignum_to_hex(&current.y));
        // if (i<debug_counter) bn_print("2 current.y: ", &current.y);
        // if (i>1) {
        //     printf("### Breaking at i: %d\n", i);
        //     break; // TODO: remove this        
        // }
    }

    // // printf("Final x: %s\n", bignum_to_hex(&result.x));
    // bn_print("Final x: ", &result.x);
    // // printf("Final y: %s\n", bignum_to_hex(&result.y));
    // bn_print("Final y: ", &result.y);
    // printf("-- ec_point_scalar_mul --\n");
    return result;
}
// Public key derivation --

__global__ void testKernel(BIGNUM* d_private_keys, EC_POINT* d_public_keys) {
    int tid = blockIdx.x * blockDim.x + threadIdx.x; // Global thread ID
    clock_t start = clock64();
    // printf("Thread %d - Starting execution\n", tid);

    // Addition
    BIGNUM a;
    BIGNUM b;
    BIGNUM curveOrder;
    BIGNUM newKey;

    init_zero(&a);
    init_zero(&b);
    init_zero(&curveOrder);
    init_zero(&newKey);

    // BN_ULONG a_d[4];
    // BN_ULONG b_d[4];

    // Initialize a
    // C17747B1566D9FE8AB7087E3F0C50175B788A1C84F4C756C405000A0CA2248E1
    BN_ULONG a_values[MAX_BIGNUM_SIZE] = {
        0xC17747B1566D9FE8,
        0xAB7087E3F0C50175,
        0xB788A1C84F4C756C,
        0x405000A0CA2248E1
        };
    for (int j = 0; j < TEST_BIGNUM_WORDS; ++j) {
            a.d[j] = a_values[j];
        }
    a.neg = 0;
    a.top = 4;

    // Initialize b
    // 6C91CEA9CF0CAC55A7596D16B56D2AEFD204BB99DD677993158A7E6564F93CDF
    BN_ULONG b_values[MAX_BIGNUM_SIZE] = {
        0x6C91CEA9CF0CAC55,
        0xA7596D16B56D2AEF,
        0xD204BB99DD677993,
        0x158A7E6564F93CDF
        };
    for (int j = 0; j < TEST_BIGNUM_WORDS; ++j) {
            b.d[j] = b_values[j];
        }
    b.neg = 0;
    b.top = 4;

    BN_ULONG curveOrder_values[MAX_BIGNUM_SIZE] = {
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
    init_zero(&m);
    m.d[0] = 0x64; // 100
    
    BIGNUM tmp;
    init_zero(&tmp);
    bn_copy(&tmp, &newKey);
    // bn_print("\n>> bn_mod tmp: ", &tmp);
    // bn_print(">> curveOrder: ", &curveOrder);
    bn_mod(&newKey, &tmp, &curveOrder); // a = b mod c
    // bn_print("<< bn_mod newKey: ", &newKey);
    // printf("(expected): 2E09165B257A4C3E52C9F4FAA6322C66CEDE807B7D6B4EC3960820795EE5447F\n");
    // bn_print("\nPrivate key: ", &newKey);
    // printf("Thread %d - After initialization\n", tid);
    // bn_print_constant("Private key: ", &newKey, tid);
    // Derive the public key
    // printf("\nDeriving the public key..\n");
    // Initialize constants
    init_zero(&CURVE_A);
    
    // For secp256k1, CURVE_B should be initialized to 7 rather than 0
    init_zero(&CURVE_B);
    CURVE_B.d[0] = 0x7;

    BN_ULONG CURVE_GX_values[MAX_BIGNUM_SIZE] = {
        0x79BE667EF9DCBBAC,
        0x55A06295CE870B07,
        0x029BFCDB2DCE28D9,
        0x59F2815B16F81798
        };
    for (int j = 0; j < MAX_BIGNUM_SIZE; ++j) {
            CURVE_GX_d[j] = CURVE_GX_values[j];
        }

    // Generator y coordinate
    // BIGNUM CURVE_GY;
    BN_ULONG CURVE_GY_values[MAX_BIGNUM_SIZE] = {
        0x483ADA7726A3C465,
        0x5DA4FBFC0E1108A8,
        0xFD17B448A6855419,
        0x9C47D08FFB10D4B8
        };
    for (int j = 0; j < MAX_BIGNUM_SIZE; ++j) {
            CURVE_GY_d[j] = CURVE_GY_values[j];
        }

    // Initialize generator
    EC_POINT G;
    init_zero(&G.x);
    init_zero(&G.y);
    for (int j = 0; j < MAX_BIGNUM_SIZE; ++j) {
            G.x.d[j] = CURVE_GX_values[j];
            G.y.d[j] = CURVE_GY_values[j];
        }
    // reverse
    reverse_order(&G.x);
    reverse_order(&G.y);
    // find top
    G.x.top = find_top(&G.x);
    G.y.top = find_top(&G.y);

    init_zero(&CURVE_P);
    //bn_copy(&CURVE_P, &curveOrder); // CURVE_P is curveOrder_d
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
    reverse_order(&CURVE_P);
    // find top
    CURVE_P.top = find_top(&CURVE_P);
    
    // Derive public key 
    EC_POINT publicKey = ec_point_scalar_mul(&G, &newKey, &CURVE_P, &CURVE_A);

    // Store the results in global memory for test purposes
    bn_copy(&d_private_keys[tid], &newKey);
    bn_copy(&d_public_keys[tid].x, &publicKey.x);
    bn_copy(&d_public_keys[tid].y, &publicKey.y);
    
    // Print public key
    // printf("Thread %d - After public key derivation\n", tid);
    // bn_print_constant("Public key x: ", &publicKey.x, tid);
    // bn_print_constant("Public key y: ", &publicKey.y, tid);
    record_function(FN_MAIN, start);
    // Only print performance report for thread 0 to avoid clutter
    if (tid == 0) {
        print_performance_report();
    }
}

int main() {
    
    const int THREADS_PER_BLOCK = 2;
    // const int THREADS_PER_BLOCK = 192; // 344 seconds
    // const int THREADS_PER_BLOCK = 200; // stuck
    // const int THREADS_PER_BLOCK = 224; // stuck
    // const int THREADS_PER_BLOCK = 256; // A good balance between occupancy and flexibility
    
    const int NUM_BLOCKS = 128; // One block per SM
    
    const int TOTAL_THREADS = THREADS_PER_BLOCK * NUM_BLOCKS; // 32,768 total threads
    // Allocate memory for results
    BIGNUM* h_private_keys = new BIGNUM[TOTAL_THREADS];
    EC_POINT* h_public_keys = new EC_POINT[TOTAL_THREADS];
    
    BIGNUM* d_private_keys;
    EC_POINT* d_public_keys;

    // Allocate device memory
    cudaMalloc(&d_private_keys, TOTAL_THREADS * sizeof(BIGNUM));
    cudaMalloc(&d_public_keys, TOTAL_THREADS * sizeof(EC_POINT));

    // Launch kernel
    testKernel<<<NUM_BLOCKS, THREADS_PER_BLOCK>>>(d_private_keys, d_public_keys);

    // Check for errors
    cudaError_t err = cudaGetLastError();
    if (err != cudaSuccess) {
        printf("Error: %s\n", cudaGetErrorString(err));
        return -1;
    }

    // Copy results back to host
    cudaMemcpy(h_private_keys, d_private_keys, TOTAL_THREADS * sizeof(BIGNUM), cudaMemcpyDeviceToHost);
    cudaMemcpy(h_public_keys, d_public_keys, TOTAL_THREADS * sizeof(EC_POINT), cudaMemcpyDeviceToHost);

    // Save results to CSV file
    std::ofstream outfile("all_results.csv");
    outfile << "Thread,Key,Value\n";

    for (int i = 0; i < TOTAL_THREADS; i++) {
        outfile << i << ",Private Key,";
        for (int j = MAX_BIGNUM_SIZE - 1; j >= 0; j--) {
            outfile << std::setfill('0') << std::setw(16) << std::hex << h_private_keys[i].d[j];
        }
        outfile << "\n";

        outfile << i << ",Public Key X,";
        for (int j = MAX_BIGNUM_SIZE - 1; j >= 0; j--) {
            outfile << std::setfill('0') << std::setw(16) << std::hex << h_public_keys[i].x.d[j];
        }
        outfile << "\n";

        outfile << i << ",Public Key Y,";
        for (int j = MAX_BIGNUM_SIZE - 1; j >= 0; j--) {
            outfile << std::setfill('0') << std::setw(16) << std::hex << h_public_keys[i].y.d[j];
        }
        outfile << "\n";
    }

    outfile.close();

    // Free memory
    delete[] h_private_keys;
    delete[] h_public_keys;
    cudaFree(d_private_keys);
    cudaFree(d_public_keys);

    cudaDeviceSynchronize();
    cudaDeviceReset();
    return 0;
}
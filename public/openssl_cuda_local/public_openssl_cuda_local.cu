#include <fstream>
#include <iomanip>
#include <stdio.h>
#include <cuda.h>
#include "bignum.h"

#define TEST_BIGNUM_WORDS 4

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
    reverse_order(&a, TEST_BIGNUM_WORDS);
    reverse_order(&b, TEST_BIGNUM_WORDS);
    reverse_order(&curveOrder, TEST_BIGNUM_WORDS);

    // Print inputs
    // bn_print(">> bn_add a: ", &a);
    // bn_print(">> bn_add b: ", &b);

    // Add A and B
    //bn_print(">> bn_add newKey: ", &newKey);
    bn_add(&newKey, &a, &b); // result = a + b
    //bn_print("<< bn_add newKey: ", &newKey);

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
    reverse_order(&G.x, TEST_BIGNUM_WORDS);
    reverse_order(&G.y, TEST_BIGNUM_WORDS);
    // find top
    G.x.top = find_top(&G.x);
    G.y.top = find_top(&G.y);

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
    
    // Derive public key 
    EC_POINT publicKey = ec_point_scalar_mul(&G, &newKey, &CURVE_P, &CURVE_A);
    //EC_POINT publicKey = ec_point_scalar_mul_optimized(&G, &newKey, &CURVE_P, &CURVE_A);

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
    
    const int THREADS_PER_BLOCK = 1;
    // const int THREADS_PER_BLOCK = 192; // 344 seconds (now stuck)
    // const int THREADS_PER_BLOCK = 200; // stuck
    // const int THREADS_PER_BLOCK = 224; // stuck
    // const int THREADS_PER_BLOCK = 256; // A good balance between occupancy and flexibility
    
    // const int NUM_BLOCKS = 128; // One block per SM
    const int NUM_BLOCKS = 1;

    
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
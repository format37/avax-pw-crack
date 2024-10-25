#include <stdio.h>
#include <stdlib.h>
#include "bignum.h"

// Test case structure 
__device__ struct mont_test_case {
    const char* a_hex;   
    const char* b_hex;    
    const char* n_hex;    
};

// Convert hex string to BIGNUM_CUDA
__device__ void hex2bn_cuda(BIGNUM_CUDA *bn, const char *hex) {
    init_zero(bn);
    int len = 0;
    while(hex[len] != '\0') len++;
    
    // Process hex string in chunks of 16 chars (64 bits)
    int chunks = (len + 15) / 16;
    for(int i = 0; i < chunks && i < MAX_BIGNUM_SIZE; i++) {
        BN_ULONG val = 0;
        int start = len - (i + 1) * 16;
        if(start < 0) start = 0;
        int chunk_size = len - i * 16 - start;
        
        for(int j = 0; j < chunk_size; j++) {
            char c = hex[start + j];
            int digit;
            if(c >= '0' && c <= '9') digit = c - '0';
            else if(c >= 'A' && c <= 'F') digit = c - 'A' + 10;
            else if(c >= 'a' && c <= 'f') digit = c - 'a' + 10;
            else continue;
            
            val = (val << 4) | digit;
        }
        bn->d[i] = val;
        if(val != 0) bn->top = i + 1;
    }
    if(bn->top == 0) bn->top = 1;
}

__device__ struct mont_test_case test_cases[] = {
    // Test 1: Small numbers (32-bit)
    {
        "11111111",  // a
        "22222222",  // b
        "FFFFFFFF"   // n
    },
    
    // Test 2: 64-bit numbers
    {
        "FFFFFFFFFFFFFFFF",
        "FFFFFFFFFFFFFFFF", 
        "FFFFFFFFFFFFFFFD"
    },
    
    // Test 3: 128-bit numbers
    {
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD"
    }
};

// Test function
__device__ void run_mont_test(const struct mont_test_case *test) {
    // Create bignums
    BIGNUM_CUDA a, b, n, r;
    init_zero(&a);
    init_zero(&b);
    init_zero(&n);
    init_zero(&r);
    
    // Convert test values
    hex2bn_cuda(&a, test->a_hex);
    hex2bn_cuda(&b, test->b_hex);
    hex2bn_cuda(&n, test->n_hex);
    
    // Create and initialize Montgomery context
    BN_MONT_CTX_CUDA *mont = BN_MONT_CTX_new_cuda();
    if(mont == NULL) {
        printf("Failed to create Montgomery context\n");
        return;
    }
    
    // Set up Montgomery context
    if(!BN_MONT_CTX_set_cuda(mont, &n)) {
        printf("Failed to initialize Montgomery context\n");
        return;
    }
    
    printf("\nTest inputs:\n");
    bn_print("a = ", &a);
    bn_print("b = ", &b);
    bn_print("n = ", &n);
    
    // Perform Montgomery multiplication
    if(!BN_mod_mul_montgomery_cuda(&r, &a, &b, mont)) {
        printf("Montgomery multiplication failed\n");
        return;
    }
    
    printf("\nResult:\n");
    bn_print("r = ", &r);
    
    // Print Montgomery context values
    printf("\nMontgomery Context:\n");
    bn_print("N (modulus) = ", &mont->N);
    printf("N0[0] = %016llx\n", mont->n0[0]);
    printf("N0[1] = %016llx\n", mont->n0[1]);
    bn_print("RR = ", &mont->RR);
    
    printf("\n");
    
    // Free memory
    free(mont);
}

__global__ void test_montgomery() {
    for(int i = 0; i < sizeof(test_cases)/sizeof(test_cases[0]); i++) {
        printf("\n=== Test case %d ===\n", i + 1);
        run_mont_test(&test_cases[i]);
    }
}

int main() {
    test_montgomery<<<1,1>>>();
    cudaDeviceSynchronize();
    return 0;
}
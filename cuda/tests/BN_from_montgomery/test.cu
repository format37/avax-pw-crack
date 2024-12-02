#include <stdio.h>
#include <stdlib.h>
#include "bignum.h"
#include "montgomery.h"
#include "point.h"

// Test case structure to mirror OpenSSL test format
__device__ struct mont_test_case {
    const char* r_hex;    // Input value in Montgomery form
    const char* expected_hex;  // Expected output in normal form
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
    bn->neg = 0;
}

// Test cases that mirror the OpenSSL test inputs
__device__ struct mont_test_case test_cases[] = {
    {
        "01000003D1",  // Input in Montgomery form
        "0000000001"   // Expected output in normal form
    },
    {
        "9981E643E9089F48979F48C033FD129C231E295329BC66DBD7362E5A487E2097",  // Input
        "1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF"   // Expected
    },
    {
        "CF3F851FD4A582D670B6B59AAC19C1368DFC5D5D1F1DC64DB15EA6D2D3DBABE2",  // Input
        "FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210"   // Expected
    }
};

__device__ void run_from_montgomery_test(const struct mont_test_case *test) {
    // Create bignums
    BIGNUM_CUDA r, ret, n;
    init_zero(&r);
    init_zero(&ret);
    init_zero(&n);
    
    // Initialize the modulus (secp256k1's p)
    n.d[3] = 0xFFFFFFFFFFFFFFFF;
    n.d[2] = 0xFFFFFFFFFFFFFFFF;
    n.d[1] = 0xFFFFFFFFFFFFFFFF;
    n.d[0] = 0xFFFFFFFEFFFFFC2F;
    n.top = 4;
    n.neg = 0;
    
    // Convert test input
    hex2bn_cuda(&r, test->r_hex);

    // Create Montgomery context
    BN_MONT_CTX_CUDA mont;
    BN_MONT_CTX_set(&mont, &n);

    BIGNUM_CUDA n_prime;
    init_zero(&n_prime);
    n_prime.d[0] = 0xd838091dd2253531;
    n_prime.top = 1;
    n_prime.neg = 0;

    // Set n_prime in montgomery context
    mont.n_prime = n_prime;

    printf("\nTest input:\n");
    bn_print_no_fuse("r (Montgomery form): ", &r);
    bn_print_no_fuse("modulus n: ", &n);
    
    // Call bn_from_montgomery_word
    bn_from_montgomery_word(&ret, &r, &mont);
    
    // Convert expected result for comparison
    BIGNUM_CUDA expected;
    init_zero(&expected);
    hex2bn_cuda(&expected, test->expected_hex);
    
    printf("\nResults:\n");
    bn_print_no_fuse("got:      ", &ret);
    bn_print_no_fuse("expected: ", &expected);
    
    // Compare results
    if (bn_cmp(&ret, &expected) == 0) {
        printf("Test PASSED\n");
    } else {
        printf("Test FAILED\n");
    }
}

__global__ void test_from_montgomery() {
    printf("Running BN_from_montgomery tests...\n");
    for(int i = 0; i < sizeof(test_cases)/sizeof(test_cases[0]); i++) {
        printf("\n=== Test case %d ===\n", i + 1);
        run_from_montgomery_test(&test_cases[i]);
    }
}

int main() {
    test_from_montgomery<<<1,1>>>();
    cudaDeviceSynchronize();
    return 0;
}
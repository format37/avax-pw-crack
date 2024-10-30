#include <stdio.h>
#include <stdlib.h>
#include "bignum.h"
#include "point.h"

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
    bn->top = find_top_cuda(bn);
}

// __device__ struct mont_test_case test_cases[] = {
//     // Test: From Python and OpenSSL code
//     {
//         "2D",  // a = 45
//         "4C",  // b = 76
//         "65"   // n = 101
//     },
// };

__device__ struct mont_test_case test_cases[] = {
    // Test Case 1: Basic small numbers (original example)
    {
        "2D",   // a = 45
        "4C",   // b = 76
        "65"    // n = 101
    },
    
    // Test Case 2: Powers of 2
    {
        "40",   // a = 64  (2^6)
        "20",   // b = 32  (2^5)
        "61"    // n = 97
    },
    
    // Test Case 3: Large prime modulus
    {
        "FFF1", // a = 0xFFF1
        "FFF2", // b = 0xFFF2
        "FFF7"  // n = 0xFFF7
    },
    
    // Test Case 4: Edge case - operands equal to modulus minus 1
    {
        "60",   // a = 96
        "60",   // b = 96
        "61"    // n = 97
    },
    
    // Test Case 5: Edge case - one operand is 1
    {
        "01",   // a = 1
        "FF",   // b = 0xFF
        "FB"    // n = 251
    },
    
    // Test Case 6: Edge case - one operand is 0
    {
        "00",   // a = 0
        "FF",   // b = 0xFF
        "FB"    // n = 251
    },
    
    // Test Case 7: Operands larger than modulus
    {
        "12D",  // a = 301
        "191",  // b = 401
        "FB"    // n = 251
    },
    
    // Test Case 8: Modulus with specific bit pattern
    {
        "AAAA", // a = 0xAAAA
        "5555", // b = 0x5555
        "FFFB"  // n = 0xFFFB
    },
    
    // Test Case 9: Equal operands
    {
        "1234", // a = 0x1234
        "1234", // b = 0x1234
        "FFFD"  // n = 0xFFFD
    },
    
    // Test Case 10: Operations with small prime modulus
    {
        "0F",   // a = 15
        "0D",   // b = 13
        "11"    // n = 17
    }
    ,

    // Test Case 11: 128-bit max values
    {
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", // a = 2^128 - 1
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE", // b = 2^128 - 2
        "100000000000000000000000000000001"  // n = 2^128 + 1
    }
    ,

    // Test Case 12: Large prime numbers near 2^127
    {
        "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", // a = 2^127 - 1
        "80000000000000000000000000000001", // b = 2^127 + 1
        "8000000000000000000000000000000D"  // n = Large prime near 2^127
    },

    // Test Case 13: Random 128-bit numbers
    {
        "e10925726c3018dcb512f4ebf0a8835b", // Random a
        "eb772e27b51120720c3913490298d9a7", // Random b
        "fbb36e8a921f0b6e56e12b56ce3f0ad3"  // Random n
    }
};

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
    
    printf("\nTest inputs:\n");
    bn_print_no_fuse("a: ", &a);
    bn_print_no_fuse("b: ", &b);
    bn_print_no_fuse("n: ", &n);

    bn_mod_mul_montgomery(&a, &b, &n, &r);
    bn_print_no_fuse("Result: ", &r);
    
    printf("\n");
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

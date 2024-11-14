#include <stdio.h>
#include <stdlib.h>
#include "bignum.h"
#include "montgomery.h"
// #include "point.h"


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

__device__ struct mont_test_case test_cases[] = {
    {
        "7C75DD9524177D593C03889B8DCD9B1CB05FB7D2A3DA7FE8BA9F29B104E7DB13", // a
        "9981E643E9089F48979F48C033FD129C231E295329BC66DBD7362E5A487E2097", // b
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"  // n
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

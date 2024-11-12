#include <stdio.h>
#include <stdint.h>
#include "cuda_runtime.h"
#include "device_launch_parameters.h"
#include "bignum.h"

// Test case structure
struct sub_quick_test_case {
    const char* a_hex;    // First operand
    const char* b_hex;    // Second operand
    const char* n_hex;    // Modulus
};

// Convert hex string to BIGNUM_CUDA
__device__ void hex2bn(BIGNUM_CUDA* bn, const char* hex) {
    // Skip "0x" prefix if present
    if (hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X')) {
        hex += 2;
    }

    init_zero(bn);
    int len = 0;
    while (hex[len] != '\0') len++;
    
    int word_index = 0;
    BN_ULONG current_word = 0;
    int bits_in_current_word = 0;
    
    // Process hex string from right to left
    for (int i = len - 1; i >= 0; i--) {
        char c = hex[i];
        uint8_t value;
        
        if (c >= '0' && c <= '9') {
            value = c - '0';
        } else if (c >= 'a' && c <= 'f') {
            value = c - 'a' + 10;
        } else if (c >= 'A' && c <= 'F') {
            value = c - 'A' + 10;
        } else {
            continue;  // Skip invalid characters
        }

        current_word |= ((BN_ULONG)value << bits_in_current_word);
        bits_in_current_word += 4;

        if (bits_in_current_word >= BN_ULONG_NUM_BITS) {
            bn->d[word_index++] = current_word;
            current_word = 0;
            bits_in_current_word = 0;
        }
    }

    // Handle any remaining bits
    if (bits_in_current_word > 0) {
        bn->d[word_index++] = current_word;
    }

    bn->top = find_top_cuda(bn);
    bn->neg = 0;
}

// Print a BIGNUM in hex format with a label
__device__ void print_bn_hex(const char* label, const BIGNUM_CUDA* bn) {
    printf("%s: ", label);
    
    if (bn->top == 0 || (bn->top == 1 && bn->d[0] == 0)) {
        printf("0\n");
        return;
    }

    #ifdef BN_128
        // Handle 128-bit words
        for (int i = bn->top - 1; i >= 0; i--) {
            unsigned __int128 word = bn->d[i];
            uint64_t high = (uint64_t)(word >> 64);
            uint64_t low = (uint64_t)word;
            if (i == bn->top - 1) {
                if (high != 0) {
                    printf("%lX%016lX", high, low);
                } else {
                    printf("%lX", low);
                }
            } else {
                printf("%016lX%016lX", high, low);
            }
        }
    #else
        // Handle 64-bit words
        for (int i = bn->top - 1; i >= 0; i--) {
            if (i == bn->top - 1) {
                printf("%lX", bn->d[i]);
            } else {
                printf("%016lX", bn->d[i]);
            }
        }
    #endif
    printf("\n");
}

// Run a single test case
__device__ void run_sub_quick_test(const struct sub_quick_test_case* test) {
    BIGNUM_CUDA a, b, n, r;
    
    // Initialize numbers
    hex2bn(&a, test->a_hex);
    hex2bn(&b, test->b_hex);
    hex2bn(&n, test->n_hex);
    init_zero(&r);

    // Print input values
    printf("\nTest inputs:\n");
    print_bn_hex("a", &a);
    print_bn_hex("b", &b);
    print_bn_hex("n", &n);

    // Print bit lengths for debugging
    printf("\nBit lengths:\n");
    printf("a bits: %d\n", bn_bit_length(&a));
    printf("b bits: %d\n", bn_bit_length(&b));
    printf("n bits: %d\n", bn_bit_length(&n));

    // Perform modular subtraction
    if (!bn_mod_sub_quick(&r, &a, &b, &n)) {
        printf("Modular subtraction failed\n");
        return;
    }

    printf("\nResult:\n");
    print_bn_hex("r (final result)", &r);
}

__global__ void test_kernel() {
    // Define test cases
    struct sub_quick_test_case test_cases[] = {
        // Test Case 1: OpenSSL example (128-bit numbers)
        {
            "E10925726C3018DCB512F4EBF0A8835B",
            "EB772E27B51120720C3913490298D9A7",
            "FBB36E8A921F0B6E56E12B56CE3F0AD3"
        }
        // Add more test cases here as needed
    };

    // Run test cases
    size_t num_tests = sizeof(test_cases) / sizeof(test_cases[0]);
    for (size_t i = 0; i < num_tests; i++) {
        printf("\n=== Test case %zu ===\n", i + 1);
        run_sub_quick_test(&test_cases[i]);
    }
}

// Host function to launch the test
void run_bn_mod_sub_quick_test() {
    test_kernel<<<1, 1>>>();
    cudaDeviceSynchronize();
    cudaError_t error = cudaGetLastError();
    if (error != cudaSuccess) {
        printf("CUDA error: %s\n", cudaGetErrorString(error));
    }
}

int main(void) {
    // Run the CUDA test
    run_bn_mod_sub_quick_test();
    return 0;
}
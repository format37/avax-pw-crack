#include <stdio.h>
#include <stdint.h>
#include "cuda_runtime.h"
#include "device_launch_parameters.h"
#include "bignum.h"
#include "montgomery.h"
#include "point.h"

// Test case structure
struct field_inv_test_case {
    const char* a_hex;    // Input value to invert
    const char* p_hex;    // Prime modulus
    const char* expected_hex; // Expected result
    bool should_succeed;  // Whether inversion should succeed
};

// Helper function to convert hex string to BIGNUM_CUDA
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

// Helper function to verify the result
__device__ bool verify_inverse(const BIGNUM_CUDA* a, const BIGNUM_CUDA* inv, const BIGNUM_CUDA* p) {
    BIGNUM_CUDA product;
    init_zero(&product);
    
    // Compute a * inv mod p
    bn_mod_mul(&product, a, inv, p);
    
    // Check if the result is 1
    return (product.top == 1 && product.d[0] == 1);
}

// Print a BIGNUM in hex format
__device__ void print_bn_hex(const char* label, const BIGNUM_CUDA* bn) {
    printf("%s: ", label);
    
    if (bn->neg) printf("-");
    
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
__device__ bool run_field_inv_test(const struct field_inv_test_case* test, int test_num) {
    BIGNUM_CUDA a, p, expected, result;
    bool test_passed = true;
    
    // Initialize numbers
    hex2bn(&a, test->a_hex);
    hex2bn(&p, test->p_hex);
    if (test->expected_hex) {
        hex2bn(&expected, test->expected_hex);
    }
    init_zero(&result);

    // Print test case information
    printf("\nTest Case %d:\n", test_num);
    printf("Computing inverse of:\n");
    print_bn_hex("a", &a);
    print_bn_hex("p (modulus)", &p);
    
    // Compute inverse
    int ret = ossl_ec_GFp_mont_field_inv(&a, &result, &p);
    
    // Check if result matches expectations
    if (ret == test->should_succeed) {
        if (ret) {
            print_bn_hex("Computed inverse", &result);
            
            // Verify the inverse by multiplication
            if (verify_inverse(&a, &result, &p)) {
                printf("Verification passed: (a * a^-1) mod p = 1\n");
            } else {
                printf("FAILED: Verification failed - inverse is incorrect\n");
                test_passed = false;
            }
            
            // If expected result provided, verify it matches
            if (test->expected_hex) {
                if (bn_cmp(&result, &expected) == 0) {
                    printf("Result matches expected value\n");
                } else {
                    printf("FAILED: Result does not match expected value\n");
                    print_bn_hex("Expected", &expected);
                    test_passed = false;
                }
            }
        } else {
            printf("Inversion failed as expected\n");
        }
    } else {
        printf("FAILED: Expected %s but got %s\n", 
               test->should_succeed ? "success" : "failure",
               ret ? "success" : "failure");
        test_passed = false;
    }
    
    return test_passed;
}

__global__ void test_kernel() {
    // Define test cases
    struct field_inv_test_case test_cases[] = {
        // Test Case 1: Simple valid case
        {
            "2",  // a
            "17", // p (prime modulus)
            "9",  // expected result (2 * 9 ≡ 1 mod 17)
            true  // should succeed
        },
        
        // Test Case 2: Zero input (should fail)
        {
            "0",
            "17",
            NULL,
            false
        },
        
        // Test Case 3: Large numbers from actual ECC usage
        // These values are from secp256k1
        {
            "9075B4EE4D4788CABB49F7F81C221151FA2F68914D0AA833388FA11FF621A970", // a
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",    // p
            "B7E31A064ED74D314DE79011C5F0A46AC155602353DC3D340FBEAEEC9767A6A6", // expected
            true
        }
    };

    // Run all test cases
    int num_tests = sizeof(test_cases) / sizeof(test_cases[0]);
    int passed = 0;
    
    printf("Running %d test cases for field inversion...\n", num_tests);
    
    for (int i = 0; i < num_tests; i++) {
        if (run_field_inv_test(&test_cases[i], i + 1)) {
            passed++;
        }
    }
    
    printf("\nTest Summary: %d/%d tests passed\n", passed, num_tests);
}

// Host function to launch the test
void run_field_inv_tests() {
    test_kernel<<<1, 1>>>();
    cudaDeviceSynchronize();
    cudaError_t error = cudaGetLastError();
    if (error != cudaSuccess) {
        printf("CUDA error: %s\n", cudaGetErrorString(error));
    }
}

int main(void) {
    run_field_inv_tests();
    return 0;
}
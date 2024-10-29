#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include "internal/cryptlib.h"
#include "bn_local.h"

/* Test case structure */
struct mont_test_case {
    const char* a_hex;    // First operand
    const char* b_hex;    // Second operand
    const char* n_hex;    // Modulus
};

/* Print a BN in hex format with a label */
static void print_bn(const char* label, const BIGNUM* bn) {
    char* hex = BN_bn2hex(bn);
    printf("%s: %s\n", label, hex);
    OPENSSL_free(hex);
}

/* Test cases */
// static struct mont_test_case test_cases[] = {
//     // Test: From Python code
//     {
//         "2D",  // a = 45
//         "4C",  // b = 76
//         "65"   // n = 101
//     },
// };
/* Test cases */
static struct mont_test_case test_cases[] = {
    // Test Case 1: Basic small numbers
    {
        "2D",           // a = 45
        "4C",           // b = 76
        "65"            // n = 101
    },
    
    // Test Case 2: Powers of 2
    {
        "40",           // a = 64 (2^6)
        "20",           // b = 32 (2^5)
        "61"            // n = 97 (prime close to power of 2)
    },
    
    // Test Case 3: Large prime modulus
    {
        "FFF1",         // a = 0xFFF1
        "FFF2",         // b = 0xFFF2
        "FFF7"          // n = 0xFFF7 (large prime)
    },
    
    // Test Case 4: Edge case - operands equal to modulus minus 1
    {
        "60",           // a = 96 (n-1)
        "60",           // b = 96 (n-1)
        "61"            // n = 97 (prime modulus)
    },
    
    // Test Case 5: Edge case - multiplication by 1
    {
        "1",            // a = 1
        "FF",           // b = 255
        "FB"            // n = 251 (prime)
    },
    
    // Test Case 6: Edge case - multiplication by 0
    {
        "0",            // a = 0
        "FF",           // b = 255
        "FB"            // n = 251
    },
    
    // Test Case 7: Operands larger than modulus
    {
        "12D",          // a = 301 (> n)
        "191",          // b = 401 (> n)
        "FB"            // n = 251
    },
    
    // Test Case 8: Modulus with specific bit pattern
    {
        "AAAA",         // a = 0xAAAA (1010...1010)
        "5555",         // b = 0x5555 (0101...0101)
        "FFFB"          // n = 0xFFFB (prime close to power of 2)
    },
    
    // Test Case 9: Equal operands (square calculation)
    {
        "1234",         // a = 0x1234
        "1234",         // b = 0x1234
        "FFFD"          // n = 0xFFFD (prime)
    },
    
    // Test Case 10: Small prime modulus
    {
        "F",            // a = 15
        "D",            // b = 13
        "11"            // n = 17 (small prime)
    }
};

/* Run a single test case */
static void run_mont_test(const struct mont_test_case* test) {
    BN_CTX* ctx = NULL;
    BN_MONT_CTX* mont = NULL;
    BIGNUM *a = NULL, *b = NULL, *n = NULL, *r = NULL;
    BIGNUM *aRR = NULL; // a * R^2
    BIGNUM *bRR = NULL; // b * R^2

    // Create context and numbers
    ctx = BN_CTX_new();
    a = BN_new();
    b = BN_new();
    n = BN_new();
    r = BN_new();
    aRR = BN_new();
    bRR = BN_new();
    mont = BN_MONT_CTX_new();

    if (ctx == NULL || a == NULL || b == NULL || n == NULL || r == NULL || mont == NULL) {
        printf("Memory allocation failed\n");
        goto cleanup;
    }

    // Convert hex strings to BIGNUMs
    BN_hex2bn(&a, test->a_hex);
    BN_hex2bn(&b, test->b_hex);
    BN_hex2bn(&n, test->n_hex);

    // Initialize Montgomery context
    if (!BN_MONT_CTX_set(mont, n, ctx)) {
        printf("Failed to initialize Montgomery context\n");
        goto cleanup;
    }

    // Print input values
    printf("\nTest inputs:\n");
    print_bn("a", a);
    print_bn("b", b);
    print_bn("n", n);

    // Convert to Montgomery form
    if (!BN_to_montgomery(aRR, a, mont, ctx) ||
        !BN_to_montgomery(bRR, b, mont, ctx)) {
        printf("Failed to convert to Montgomery form\n");
        goto cleanup;
    }

    printf("\nMontgomery form (RR values):\n");
    print_bn("aRR", aRR);
    print_bn("bRR", bRR);

    // Perform Montgomery multiplication
    if (!BN_mod_mul_montgomery(r, aRR, bRR, mont, ctx)) {
        printf("Montgomery multiplication failed\n");
        goto cleanup;
    }

    printf("\nResult:\n");
    print_bn("r (Montgomery form)", r);

    // Convert back from Montgomery form
    if (!BN_from_montgomery(r, r, mont, ctx)) {
        printf("Failed to convert back from Montgomery form\n");
        goto cleanup;
    }

    print_bn("r (final result)", r);

    // Print the Montgomery context values for reference
    printf("\nMontgomery Context:\n");
    print_bn("N (modulus)", &mont->N);
    printf("N0: [");
#if BN_BITS2 == 64
    printf("%016lx", mont->n0[0]);
#elif BN_BITS2 == 32
    printf("%08lx", mont->n0[0]);
#endif
    printf("]\n");
    print_bn("RR", &mont->RR);

    printf("\n");

cleanup:
    BN_MONT_CTX_free(mont);
    BN_free(aRR);
    BN_free(bRR);
    BN_free(a);
    BN_free(b);
    BN_free(n);
    BN_free(r);
    BN_CTX_free(ctx);
}

int main(void) {
    size_t i;
    size_t num_tests = sizeof(test_cases) / sizeof(test_cases[0]);

    for (i = 0; i < num_tests; i++) {
        printf("\n=== Test case %zu ===\n", i + 1);
        run_mont_test(&test_cases[i]);
    }

    return 0;
}

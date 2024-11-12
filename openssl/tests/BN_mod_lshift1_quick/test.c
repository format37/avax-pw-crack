#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/err.h>

/* Test case structure */
struct lshift1_test_case {
    const char* a_hex;   // Input number
    const char* m_hex;   // Modulus
};

/* Print a BN in hex format with a label */
static void print_bn(const char* label, const BIGNUM* bn) {
    char* hex = BN_bn2hex(bn);
    printf("%s: %s\n", label, hex);
    OPENSSL_free(hex);
}

/* Test cases */
static struct lshift1_test_case test_cases[] = {
    // Test Case 1: Small numbers
    {
        "5", // a = 5 (binary 101)
        "A"  // m = 10 (after shift: 1010 = 10)
    },
    // Test Case 2: Larger numbers where shift causes mod reduction
    {
        "8000000000000000",  // Just below half of modulus
        "FFFFFFFFFFFFFFFF"   // After shift will be > modulus
    },
    // Test Case 3: Number that becomes exactly equal to modulus after shift
    {
        "7FFFFFFFFFFFFFFF",  // Half of modulus - 1
        "FFFFFFFFFFFFFFFF"   // Full modulus
    },
    // Test Case 4: Large 192-bit numbers (3 x 64-bit words)
    {
        "E10925726C3018DCB512F4EBF0A8835B",  // Input close to modulus
        "FBB36E8A921F0B6E56E12B56CE3F0AD3",  // Modulus
    }
};

/* Run a single test case */
static void run_lshift1_test(const struct lshift1_test_case* test) {
    BIGNUM *a = NULL, *m = NULL, *r = NULL;
    BN_CTX *ctx = NULL;

    // Create BN_CTX for temporary variables
    ctx = BN_CTX_new();
    if (ctx == NULL) {
        printf("Failed to create BN_CTX\n");
        goto cleanup;
    }

    // Create numbers
    a = BN_new();
    m = BN_new();
    r = BN_new();
    if (a == NULL || m == NULL || r == NULL) {
        printf("Memory allocation failed\n");
        goto cleanup;
    }

    // Convert hex strings to BIGNUMs
    BN_hex2bn(&a, test->a_hex);
    BN_hex2bn(&m, test->m_hex);

    // Print input values
    printf("\nTest inputs:\n");
    print_bn("a", a);
    print_bn("m (modulus)", m);

    // Verify preconditions
    if (BN_is_negative(a) || BN_cmp(a, m) >= 0) {
        printf("Error: Input 'a' must be non-negative and less than modulus\n");
        goto cleanup;
    }

    // Perform modular left shift by 1
    if (!BN_mod_lshift1_quick(r, a, m)) {
        printf("Modular left shift failed\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    printf("\nResult:\n");
    print_bn("r (a << 1 mod m)", r);

    // Verification: ensure result is less than modulus
    if (BN_cmp(r, m) >= 0) {
        printf("Error: Result is not properly reduced\n");
    }

    // Print additional useful information
    printf("\nBit lengths:\n");
    printf("a bits: %d\n", BN_num_bits(a));
    printf("m bits: %d\n", BN_num_bits(m));
    printf("r bits: %d\n", BN_num_bits(r));

cleanup:
    BN_CTX_free(ctx);
    BN_free(a);
    BN_free(m);
    BN_free(r);
}

int main(void) {
    size_t i;
    size_t num_tests = sizeof(test_cases) / sizeof(test_cases[0]);

    // Initialize OpenSSL error strings
    ERR_load_crypto_strings();

    for (i = 0; i < num_tests; i++) {
        printf("\n=== Test case %zu ===\n", i + 1);
        run_lshift1_test(&test_cases[i]);
    }

    // Clean up error strings
    ERR_free_strings();

    return 0;
}
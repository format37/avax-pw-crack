#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/err.h>

/* Test case structure */
struct sub_test_case {
    const char* a_hex;  // First operand
    const char* b_hex;  // Second operand
    const char* n_hex;  // Modulus
};

/* Print a BN in hex format with a label */
static void print_bn(const char* label, const BIGNUM* bn) {
    char* hex = BN_bn2hex(bn);
    printf("%s: %s\n", label, hex);
    OPENSSL_free(hex);
}

/* Test cases */
static struct sub_test_case test_cases[] = {
    // Test Case 1: 128-bit numbers
    {
        "E10925726C3018DCB512F4EBF0A8835B",
        "EB772E27B51120720C3913490298D9A7",
        "FBB36E8A921F0B6E56E12B56CE3F0AD3"
    }
    // Add more test cases here as needed
};

/* Run a single test case */
static void run_sub_test(const struct sub_test_case* test) {
    BIGNUM *a = NULL, *b = NULL, *n = NULL, *r = NULL;
    BN_CTX *ctx = NULL;

    // Create BN_CTX for temporary variables
    ctx = BN_CTX_new();
    if (ctx == NULL) {
        printf("Failed to create BN_CTX\n");
        goto cleanup;
    }

    // Create numbers
    a = BN_new();
    b = BN_new();
    n = BN_new();
    r = BN_new();
    if (a == NULL || b == NULL || n == NULL || r == NULL) {
        printf("Memory allocation failed\n");
        goto cleanup;
    }

    // Convert hex strings to BIGNUMs
    BN_hex2bn(&a, test->a_hex);
    BN_hex2bn(&b, test->b_hex);
    BN_hex2bn(&n, test->n_hex);

    // Print input values
    printf("\nTest inputs:\n");
    print_bn("a", a);
    print_bn("b", b);
    print_bn("n", n);

    // Perform modular subtraction using BN_mod_sub_quick
    if (!BN_mod_sub_quick(r, a, b, n)) {
        printf("Modular subtraction failed\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    printf("\nResult:\n");
    print_bn("r (final result)", r);

    // Print additional useful information
    printf("\nBit lengths:\n");
    printf("a bits: %d\n", BN_num_bits(a));
    printf("b bits: %d\n", BN_num_bits(b));
    printf("n bits: %d\n", BN_num_bits(n));
    printf("r bits: %d\n", BN_num_bits(r));

cleanup:
    BN_CTX_free(ctx);
    BN_free(a);
    BN_free(b);
    BN_free(n);
    BN_free(r);
}

int main(void) {
    size_t i;
    size_t num_tests = sizeof(test_cases) / sizeof(test_cases[0]);

    // Initialize OpenSSL error strings
    ERR_load_crypto_strings();

    for (i = 0; i < num_tests; i++) {
        printf("\n=== Test case %zu ===\n", i + 1);
        run_sub_test(&test_cases[i]);
    }

    // Clean up error strings
    ERR_free_strings();

    return 0;
}
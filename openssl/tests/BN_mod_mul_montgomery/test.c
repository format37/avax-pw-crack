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
static struct mont_test_case test_cases[] = {
    // Test: From Python code
    {
        "2D",  // a = 45
        "4C",  // b = 76
        "65"   // n = 101
    },
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

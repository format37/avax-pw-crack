#include <stdio.h>
#include <openssl/bn.h>
#include <openssl/err.h>

/* Utility function to print BIGNUM in hexadecimal format */
void print_bn(const char *label, const BIGNUM *bn) {
    char *hex_str = BN_bn2hex(bn);
    if (hex_str != NULL) {
        printf("%s: %s\n", label, hex_str);
        OPENSSL_free(hex_str);
    } else {
        fprintf(stderr, "Error converting BIGNUM to hex string.\n");
    }
}

int main(void) {
    /* Initialize variables */
    BN_CTX *ctx = BN_CTX_new();
    BN_MONT_CTX *mont_ctx = BN_MONT_CTX_new();
    BIGNUM *a = BN_new();    /* Base */
    BIGNUM *p = BN_new();    /* Exponent */
    BIGNUM *m = BN_new();    /* Modulus */
    BIGNUM *r = BN_new();    /* Result */

    if (ctx == NULL || mont_ctx == NULL || a == NULL || p == NULL || m == NULL || r == NULL) {
        fprintf(stderr, "Error allocating BIGNUMs or contexts.\n");
        goto cleanup;
    }

    /* Set values for a, p, and m */
    if (!BN_hex2bn(&a, "123456789ABCDEF123456789ABCDEF")) {
        fprintf(stderr, "Error setting base 'a'.\n");
        goto cleanup;
    }

    if (!BN_hex2bn(&p, "FEDCBA9876543210FEDCBA9876543210")) {
        fprintf(stderr, "Error setting exponent 'p'.\n");
        goto cleanup;
    }

    if (!BN_hex2bn(&m, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F")) {
        fprintf(stderr, "Error setting modulus 'm'.\n");
        goto cleanup;
    }

    /* Initialize Montgomery context for modulus 'm' */
    if (!BN_MONT_CTX_set(mont_ctx, m, ctx)) {
        fprintf(stderr, "Error initializing Montgomery context.\n");
        goto cleanup;
    }

    /* Perform modular exponentiation: r = a^p mod m */
    // Print inputs
    print_bn("Base (a)", a);
    print_bn("Exponent (p)", p);
    print_bn("Modulus (m)", m);
    if (!BN_mod_exp_mont(r, a, p, m, ctx, mont_ctx)) {
        fprintf(stderr, "Error in BN_mod_exp_mont.\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    /* Print the result */
    print_bn("Result (r = a^p mod m)", r);

cleanup:
    /* Free allocated resources */
    BN_free(a);
    BN_free(p);
    BN_free(m);
    BN_free(r);
    BN_CTX_free(ctx);
    BN_MONT_CTX_free(mont_ctx);

    return 0;
}

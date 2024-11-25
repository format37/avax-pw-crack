#include <stdio.h>
#include <openssl/bn.h>
#include "bn_local.h"

int main() {
    // Initialize variables
    BIGNUM *a = NULL;
    BIGNUM *r = NULL;
    BIGNUM *modulus = NULL;
    BN_CTX *ctx = NULL;
    BN_MONT_CTX *mont = NULL;

    // Create a BN_CTX structure for temporary variables
    ctx = BN_CTX_new();
    if (ctx == NULL) {
        fprintf(stderr, "Failed to create BN_CTX\n");
        return 1;
    }

    // Create BIGNUM structures
    a = BN_new();
    r = BN_new();
    modulus = BN_new();
    if (a == NULL || r == NULL || modulus == NULL) {
        fprintf(stderr, "Failed to create BIGNUMs\n");
        goto cleanup;
    }

    // Set 'a' from hexadecimal string
    if (!BN_hex2bn(&a, "02C1AC53E90530F1F2457DD8D5CCC625A561DEAAA7B691AE2293294D46232198")) {
        fprintf(stderr, "Failed to set 'a'\n");
        goto cleanup;
    }

    // Set modulus 'N'
    if (!BN_hex2bn(&modulus, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F")) {
        fprintf(stderr, "Failed to set modulus 'N'\n");
        goto cleanup;
    }

    // Create and initialize the Montgomery context
    mont = BN_MONT_CTX_new();
    if (mont == NULL) {
        fprintf(stderr, "Failed to create BN_MONT_CTX\n");
        goto cleanup;
    }

    // Initialize the Montgomery context with the modulus
    if (!BN_MONT_CTX_set(mont, modulus, ctx)) {
        fprintf(stderr, "Failed to set BN_MONT_CTX\n");
        goto cleanup;
    }

    // Manually set mont->ri to 256
    mont->ri = 256;

    // Manually set mont->RR
    mont->RR.d[0] = 0x7A2000E90A1;
    mont->RR.d[1] = 0x1;
    mont->RR.top = 2;

    // Manually set mont->n0
    mont->n0[0] = 15580212934572586289;
    mont->n0[1] = 0;

    // Perform conversion to Montgomery form: r = a * R mod N
    if (!BN_to_montgomery(r, a, mont, ctx)) {
        fprintf(stderr, "BN_to_montgomery failed\n");
        goto cleanup;
    }

cleanup:
    // Free allocated resources
    BN_free(a);
    BN_free(r);
    BN_free(modulus);
    BN_MONT_CTX_free(mont);
    BN_CTX_free(ctx);

    return 0;
}

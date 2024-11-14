#include <stdio.h>
#include <openssl/bn.h>

int main() {
    // Initialize variables
    BIGNUM *a = NULL;
    BIGNUM *b = NULL;
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
    b = BN_new();
    r = BN_new();
    modulus = BN_new();
    if (a == NULL || b == NULL || r == NULL || modulus == NULL) {
        fprintf(stderr, "Failed to create BIGNUMs\n");
        goto cleanup;
    }

    // Set 'a' and 'b' from hexadecimal strings
    // if (!BN_hex2bn(&a, "7C75DD9524177D593C03889B8DCD9B1CB05FB7D2A3DA7FE8BA9F29B104E7DB13")) {
    if (!BN_hex2bn(&a, "FBC7886CAEDE7E47DF4610663AF356CC13E42185BC0C277193D844BB3BA14C09")) {
        fprintf(stderr, "Failed to set 'a'\n");
        goto cleanup;
    }
    // if (!BN_hex2bn(&b, "9981E643E9089F48979F48C033FD129C231E295329BC66DBD7362E5A487E2097")) {
    if (!BN_hex2bn(&b, "D68A7BE82E968DE07E14AE5EC6DDC0750C483B63639976F4293AC2360880F585")) {
        fprintf(stderr, "Failed to set 'b'\n");
        goto cleanup;
    }

    // Set modulus 'N' to the secp256k1 prime: FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
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

    // Perform Montgomery multiplication: r = (a * b) mod N
    if (!BN_mod_mul_montgomery(r, a, b, mont, ctx)) {
        fprintf(stderr, "BN_mod_mul_montgomery failed\n");
        goto cleanup;
    }

cleanup:
    // Free allocated resources
    BN_free(a);
    BN_free(b);
    BN_free(r);
    BN_free(modulus);
    BN_MONT_CTX_free(mont);
    BN_CTX_free(ctx);

    return 0;
}

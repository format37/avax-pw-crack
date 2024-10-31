#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
// #include "crypto/ec.h"


int main(void) {
    // Initialize BN_CTX
    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Failed to create BN_CTX\n");
        return 1;
    }

    // Create BIGNUM scalar
    BIGNUM *scalar = BN_new();
    if (!scalar) {
        fprintf(stderr, "Failed to create scalar BIGNUM\n");
        BN_CTX_free(ctx);
        return 1;
    }

    // Set scalar to the same value as in your CUDA code
    const char *scalar_hex = "1988f4633d8e6f312f3a8fc1da0e6274f77940bb5ea3f36a571cebc1db19b147";
    if (!BN_hex2bn(&scalar, scalar_hex)) {
        fprintf(stderr, "Failed to set scalar value\n");
        BN_free(scalar);
        BN_CTX_free(ctx);
        return 1;
    }

    // Get EC_GROUP *group for secp256k1
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    if (!group) {
        fprintf(stderr, "Failed to create EC_GROUP\n");
        BN_free(scalar);
        BN_CTX_free(ctx);
        return 1;
    }

    // Get the generator point G
    const EC_POINT *G = EC_GROUP_get0_generator(group);
    if (!G) {
        fprintf(stderr, "Failed to get generator point\n");
        EC_GROUP_free(group);
        BN_free(scalar);
        BN_CTX_free(ctx);
        return 1;
    }

    // Create EC_POINT *result to store the multiplication result
    EC_POINT *result = EC_POINT_new(group);
    if (!result) {
        fprintf(stderr, "Failed to create result point\n");
        EC_GROUP_free(group);
        BN_free(scalar);
        BN_CTX_free(ctx);
        return 1;
    }

    // Perform scalar multiplication: result = scalar * G
    if (!EC_POINT_mul(group, result, NULL, G, scalar, ctx)) {
        fprintf(stderr, "Failed to perform scalar multiplication\n");
        EC_POINT_free(result);
        EC_GROUP_free(group);
        BN_free(scalar);
        BN_CTX_free(ctx);
        return 1;
    }

    // Prepare BIGNUMs to hold the affine coordinates
    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();
    if (!x || !y) {
        fprintf(stderr, "Failed to create BIGNUMs for coordinates\n");
        BN_free(x);
        BN_free(y);
        EC_POINT_free(result);
        EC_GROUP_free(group);
        BN_free(scalar);
        BN_CTX_free(ctx);
        return 1;
    }

    // Get the affine coordinates of the result point
    if (!EC_POINT_get_affine_coordinates_GFp(group, result, x, y, ctx)) {
        fprintf(stderr, "Failed to get affine coordinates\n");
        BN_free(x);
        BN_free(y);
        EC_POINT_free(result);
        EC_GROUP_free(group);
        BN_free(scalar);
        BN_CTX_free(ctx);
        return 1;
    }

    // Convert coordinates to hexadecimal strings
    char *x_hex = BN_bn2hex(x);
    char *y_hex = BN_bn2hex(y);
    if (!x_hex || !y_hex) {
        fprintf(stderr, "Failed to convert coordinates to hex\n");
        OPENSSL_free(x_hex);
        OPENSSL_free(y_hex);
        BN_free(x);
        BN_free(y);
        EC_POINT_free(result);
        EC_GROUP_free(group);
        BN_free(scalar);
        BN_CTX_free(ctx);
        return 1;
    }

    // Print the result
    printf("Resulting point:\n");
    printf("x: %s\n", x_hex);
    printf("y: %s\n", y_hex);

    // Clean up
    OPENSSL_free(x_hex);
    OPENSSL_free(y_hex);
    BN_free(x);
    BN_free(y);
    EC_POINT_free(result);
    EC_GROUP_free(group);
    BN_free(scalar);
    BN_CTX_free(ctx);

    return 0;
}

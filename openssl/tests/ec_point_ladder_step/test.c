#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/err.h>
#include "ec_local.h"

// Utility function to print EC_POINT in hex
void print_point(const char* label, const EC_GROUP *group, const EC_POINT *point, BN_CTX *ctx) {
    char *hex = EC_POINT_point2hex(group, point, POINT_CONVERSION_UNCOMPRESSED, ctx);
    if (hex) {
        printf("%s: %s\n", label, hex);
        OPENSSL_free(hex);
    } else {
        printf("%s: <error>\n", label);
    }
}

// Function to create an EC_POINT from a hex string
EC_POINT *hex_to_ec_point(const EC_GROUP *group, const char *hex, BN_CTX *ctx) {
    EC_POINT *point = EC_POINT_new(group);
    if (!point) {
        fprintf(stderr, "Failed to create EC_POINT\n");
        return NULL;
    }

    if (!EC_POINT_hex2point(group, hex, point, ctx)) {
        fprintf(stderr, "Failed to set EC_POINT from hex: %s\n", hex);
        EC_POINT_free(point);
        return NULL;
    }

    // Verify point is on the curve
    if (!EC_POINT_is_on_curve(group, point, ctx)) {
        fprintf(stderr, "Point is not on the curve\n");
        EC_POINT_free(point);
        return NULL;
    }

    return point;
}


int main(void) {

    const char *r_hex = "04C17EF51345AB15D05F2D6F222316740156371AE09084EFE61E2D6FD604D4512049A7CD60CC88F345B07CD2BEA8DE9EE8923F1D209182587CDD95081B18A8C006";

    // Initialize OpenSSL
    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Failed to create BN_CTX\n");
        return 1;
    }

    // Create the secp256k1 group
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    if (!group) {
        fprintf(stderr, "Failed to create EC_GROUP\n");
        BN_CTX_free(ctx);
        return 1;
    }

    // Create points
    EC_POINT *r = EC_POINT_new(group);
    EC_POINT *s = EC_POINT_new(group);
    EC_POINT *p = EC_POINT_new(group);

    // Set base point (generator)
    if (!EC_POINT_copy(p, EC_GROUP_get0_generator(group))) {
        fprintf(stderr, "Failed to copy generator point\n");
        goto err;
    }    

    // Create initial values for r and s using generator point
    if (!EC_POINT_copy(r, p) ||
        !EC_POINT_dbl(group, r, p, ctx)) {
        fprintf(stderr, "Failed to initialize r\n");
        goto err;
    }

    if (!EC_POINT_copy(s, p)) {
        fprintf(stderr, "Failed to initialize s\n");
        goto err;
    }

    if (!r || !s || !p) {
        fprintf(stderr, "Failed to create EC_POINTs\n");
        goto err;
    }

    // Verify points are on curve
    if (!EC_POINT_is_on_curve(group, p, ctx) ||
        !EC_POINT_is_on_curve(group, r, ctx) ||
        !EC_POINT_is_on_curve(group, s, ctx)) {
        fprintf(stderr, "Points are not on curve\n");
        goto err;
    }

    // Print initial points
    print_point("Initial point: p (generator)", group, p, ctx);
    print_point("Initial point: r", group, r, ctx);
    print_point("Initial point: s", group, s, ctx);

    // Perform ladder step
    if (!ec_point_ladder_step(group, r, s, p, ctx)) {
        fprintf(stderr, "ec_point_ladder_step failed\n");
        goto err;
    }

    // Print resulting points
    print_point("After ladder step: r", group, r, ctx);
    print_point("After ladder step: s", group, s, ctx);

    printf("\nTest completed successfully\n");

err:
    EC_POINT_free(r);
    EC_POINT_free(s);
    EC_POINT_free(p);
    EC_GROUP_free(group);
    BN_CTX_free(ctx);
    return 0;
}
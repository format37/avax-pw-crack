#include <stdio.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/err.h>
#include "ec_local.h"

// Function prototype
int ec_point_ladder_step(const EC_GROUP *group, EC_POINT *r, EC_POINT *s, EC_POINT *p, BN_CTX *ctx);
int ec_point_ladder_pre(const EC_GROUP *group, EC_POINT *r, EC_POINT *s, EC_POINT *p, BN_CTX *ctx);

// Utility function to print point details
void print_point(const char* label, const EC_POINT *point, const EC_GROUP *group, BN_CTX *ctx) {
    char *point_hex = NULL;
    BIGNUM *x = NULL;
    BIGNUM *y = NULL;
    char *x_hex = NULL;
    char *y_hex = NULL;

    x = BN_new();
    y = BN_new();

    if (!x || !y) {
        fprintf(stderr, "%s: Failed to create BIGNUMs\n", label);
        goto cleanup;
    }

    if (!EC_POINT_get_affine_coordinates(group, point, x, y, ctx)) {
        fprintf(stderr, "%s: <error getting coordinates>\n", label);
        goto cleanup;
    }

    point_hex = EC_POINT_point2hex(group, point, POINT_CONVERSION_UNCOMPRESSED, ctx);
    x_hex = BN_bn2hex(x);
    y_hex = BN_bn2hex(y);

    if (!point_hex || !x_hex || !y_hex) {
        fprintf(stderr, "%s: Failed to convert to hex\n", label);
        goto cleanup;
    }

    printf("%s: %s\n", label, point_hex);
    printf("  X: %s\n", x_hex);
    printf("  Y: %s\n", y_hex);

cleanup:
    OPENSSL_free(point_hex);
    OPENSSL_free(x_hex);
    OPENSSL_free(y_hex);
    BN_free(x);
    BN_free(y);
}

int main(void) {
    BN_CTX *ctx = NULL;
    EC_GROUP *group = NULL;
    EC_POINT *r = NULL;
    EC_POINT *s = NULL;
    EC_POINT *p = NULL;
    BIGNUM *x = NULL;
    BIGNUM *y = NULL;
    int ret = 0;

    // Initialize OpenSSL
    ctx = BN_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Failed to create BN_CTX\n");
        goto cleanup;
    }

    // Create the secp256k1 group
    group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    if (!group) {
        fprintf(stderr, "Failed to create group\n");
        goto cleanup;
    }

    // Create points
    r = EC_POINT_new(group);
    s = EC_POINT_new(group);
    p = EC_POINT_new(group);
    if (!r || !s || !p) {
        fprintf(stderr, "Failed to create points\n");
        goto cleanup;
    }

    // Initialize input point p with generator coordinates 
    // if (!BN_hex2bn(&x, "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798") ||
    //     !BN_hex2bn(&y, "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8") ||
    //     !EC_POINT_set_affine_coordinates(group, p, x, y, ctx)) {
    //     fprintf(stderr, "Failed to set generator coordinates\n");
    //     goto cleanup;
    // }

    // Initialize p with the group's generator point
    if (!EC_POINT_copy(p, EC_GROUP_get0_generator(group))) {
        fprintf(stderr, "Failed to copy generator\n");
        goto cleanup;
    }


    // x = BN_new();
    // y = BN_new();
    // if (!x || !y) {
    //     fprintf(stderr, "Failed to create BIGNUMs\n");
    //     goto cleanup;
    // }

    // if (!BN_hex2bn(&x, "9981E643E9089F48979F48C033FD129C231E295329BC66DBD7362E5A487E2097") ||
    //     !BN_hex2bn(&y, "CF3F851FD4A582D670B6B59AAC19C1368DFC5D5D1F1DC64DB15EA6D2D3DBABE2") ||
    //     !EC_POINT_set_affine_coordinates(group, p, x, y, ctx)) {
    //     fprintf(stderr, "Failed to set generator coordinates\n");
    //     goto cleanup;
    // }

    // Call the ladder_pre function
    if (!ec_point_ladder_pre(group, r, s, p, ctx)) {
        fprintf(stderr, "ladder_pre failed\n");
        goto cleanup;
    }

    // printf("\nAfter ladder_pre:\n");
    printf("\ntest complete")

    ret = 1;

cleanup:
    BN_free(x);
    BN_free(y);
    EC_POINT_free(r);
    EC_POINT_free(s);
    EC_POINT_free(p);
    EC_GROUP_free(group);
    BN_CTX_free(ctx);

    if (!ret)
        ERR_print_errors_fp(stderr);

    return ret ? 0 : 1;
}
#include <stdio.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <string.h>

/**
 * Reads elliptic curve test cases from 'point_add_cases_full.txt' and performs point addition
 * and point doubling using OpenSSL. The curve used for operations is secp256k1.
 *
 * The test cases have the following format:
 * Px Py Qx Qy (P+Q)x (P+Q)y (P+P)x (P+P)y
 * where P and Q are points on the elliptic curve.
 */

void print_bn(const char* label, const BIGNUM* bn) {
    char* hex = BN_bn2hex(bn);
    printf("%s %s\n", label, hex);
    OPENSSL_free(hex);
}

int main() {
    // Open the test cases file
    FILE* file = fopen("../../../point_add_cases_full.txt", "r");
    if (!file) {
        fprintf(stderr, "Could not open point_add_cases_full.txt\n");
        return 1;
    }

    char line[1024];
    BN_CTX *ctx = BN_CTX_new();

    // Create and set the curve parameters for secp256k1
    int curve_nid = NID_secp256k1;
    EC_GROUP *group = EC_GROUP_new_by_curve_name(curve_nid);

    if (group == NULL) {
        fprintf(stderr, "Failed to create EC_GROUP for secp256k1\n");
        return 1;
    }

    // Read each line from the file and perform calculations
    while (fgets(line, sizeof(line), file)) {
        char x1_hex[65], y1_hex[65], x2_hex[65], y2_hex[65];
        char rx_hex[65], ry_hex[65], rdx_hex[65], rdy_hex[65];

        sscanf(line, "%64s %64s %64s %64s %64s %64s %64s %64s",
               x1_hex, y1_hex, x2_hex, y2_hex,
               rx_hex, ry_hex, rdx_hex, rdy_hex);

        BIGNUM *x1 = BN_new(), *y1 = BN_new();
        BIGNUM *x2 = BN_new(), *y2 = BN_new();
        BIGNUM *x_result = BN_new(), *y_result = BN_new();
        BIGNUM *x_result_double = BN_new(), *y_result_double = BN_new();

        // Convert hex inputs to BIGNUM
        BN_hex2bn(&x1, x1_hex);
        BN_hex2bn(&y1, y1_hex);
        BN_hex2bn(&x2, x2_hex);
        BN_hex2bn(&y2, y2_hex);

        // Expected results
        BIGNUM *expected_rx = BN_new();
        BIGNUM *expected_ry = BN_new();
        BIGNUM *expected_rdx = BN_new();
        BIGNUM *expected_rdy = BN_new();

        BN_hex2bn(&expected_rx, rx_hex);
        BN_hex2bn(&expected_ry, ry_hex);
        BN_hex2bn(&expected_rdx, rdx_hex);
        BN_hex2bn(&expected_rdy, rdy_hex);

        EC_POINT *p1 = EC_POINT_new(group);
        EC_POINT *p2 = EC_POINT_new(group);
        EC_POINT *result = EC_POINT_new(group);
        EC_POINT *result_double = EC_POINT_new(group);

        EC_POINT_set_affine_coordinates(group, p1, x1, y1, ctx);
        EC_POINT_set_affine_coordinates(group, p2, x2, y2, ctx);

        // Perform addition
        EC_POINT_add(group, result, p1, p2, ctx);
        EC_POINT_dbl(group, result_double, p1, ctx);

        // Get the resulting coordinates
        EC_POINT_get_affine_coordinates(group, result, x_result, y_result, ctx);
        EC_POINT_get_affine_coordinates(group, result_double, x_result_double, y_result_double, ctx);

        // Validate the results
        int add_correct = (BN_cmp(x_result, expected_rx) == 0) && (BN_cmp(y_result, expected_ry) == 0);
        int dbl_correct = (BN_cmp(x_result_double, expected_rdx) == 0) && (BN_cmp(y_result_double, expected_rdy) == 0);

        printf("%s %s %s %s -> Addition %s, Doubling %s\n",
               x1_hex, y1_hex, x2_hex, y2_hex,
               add_correct ? "PASS" : "FAIL",
               dbl_correct ? "PASS" : "FAIL");

        // Free allocated resources
        BN_free(x1); BN_free(y1);
        BN_free(x2); BN_free(y2);
        BN_free(x_result); BN_free(y_result);
        BN_free(x_result_double); BN_free(y_result_double);
        BN_free(expected_rx); BN_free(expected_ry);
        BN_free(expected_rdx); BN_free(expected_rdy);

        EC_POINT_free(p1); EC_POINT_free(p2);
        EC_POINT_free(result); EC_POINT_free(result_double);
    }

    fclose(file);

    // Free context and group
    BN_CTX_free(ctx);
    EC_GROUP_free(group);

    return 0;
}

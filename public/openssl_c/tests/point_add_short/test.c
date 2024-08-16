#include <stdio.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>

void print_bn(const char* label, const BIGNUM* bn) {
    char* dec = BN_bn2dec(bn);
    printf("%s %s\n", label, dec);
    OPENSSL_free(dec);
}

void test() {
    // Define the small curve parameters
    const char *p_hex = "11";  // 17 in decimal
    const char *a_hex = "2";
    const char *b_hex = "2";

    // Define the test points
    const char *x1_hex = "5";
    const char *y1_hex = "1";
    const char *x2_hex = "6";
    const char *y2_hex = "3";

    BN_CTX *ctx = BN_CTX_new();
    
    BIGNUM *p = BN_new();
    BIGNUM *a = BN_new();
    BIGNUM *b = BN_new();
    BIGNUM *x1 = BN_new();
    BIGNUM *y1 = BN_new();
    BIGNUM *x2 = BN_new();
    BIGNUM *y2 = BN_new();

    BN_hex2bn(&p, p_hex);
    BN_hex2bn(&a, a_hex);
    BN_hex2bn(&b, b_hex);
    BN_hex2bn(&x1, x1_hex);
    BN_hex2bn(&y1, y1_hex);
    BN_hex2bn(&x2, x2_hex);
    BN_hex2bn(&y2, y2_hex);

    // Create a new EC_GROUP with our custom parameters
    EC_GROUP *group = EC_GROUP_new_curve_GFp(p, a, b, ctx);

    EC_POINT *p1 = EC_POINT_new(group);
    EC_POINT *p2 = EC_POINT_new(group);
    EC_POINT *result = EC_POINT_new(group);

    EC_POINT_set_affine_coordinates_GFp(group, p1, x1, y1, ctx);
    EC_POINT_set_affine_coordinates_GFp(group, p2, x2, y2, ctx);

    printf("++ point_add ++\n");
    print_bn(">> p1.x:", x1);
    print_bn(">> p1.y:", y1);
    print_bn(">> p2.x:", x2);
    print_bn(">> p2.y:", y2);
    print_bn(">> p:", p);

    // Perform point addition
    EC_POINT_add(group, result, p1, p2, ctx);

    // Retrieve the result
    BIGNUM *x_result = BN_new();
    BIGNUM *y_result = BN_new();
    EC_POINT_get_affine_coordinates_GFp(group, result, x_result, y_result, ctx);

    // Print the result
    print_bn("<< result->x:", x_result);
    print_bn("<< result->y:", y_result);

    printf("\n### OpenSSL\n");
    printf("Point Addition Test:\n");
    printf("P1 + P2 = (%s, %s)\n", BN_bn2dec(x_result), BN_bn2dec(y_result));

    // Test point doubling
    EC_POINT_dbl(group, result, p1, ctx);
    EC_POINT_get_affine_coordinates_GFp(group, result, x_result, y_result, ctx);

    printf("\nPoint Doubling Test:\n");
    printf("P1 + P1 = (%s, %s)\n", BN_bn2dec(x_result), BN_bn2dec(y_result));

    // Free the allocated memory
    BN_free(p);
    BN_free(a);
    BN_free(b);
    BN_free(x1);
    BN_free(y1);
    BN_free(x2);
    BN_free(y2);
    BN_free(x_result);
    BN_free(y_result);
    EC_POINT_free(p1);
    EC_POINT_free(p2);
    EC_POINT_free(result);
    BN_CTX_free(ctx);
    EC_GROUP_free(group);
}

int main() {
    test();
    return 0;
}
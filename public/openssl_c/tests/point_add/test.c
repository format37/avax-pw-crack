#include <stdio.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>

void print_bn(const char* label, const BIGNUM* bn) {
    char* hex = BN_bn2hex(bn);
    printf("%s %s\n", label, hex);
    OPENSSL_free(hex);
}

int main() {
    // Define the secp256k1 curve parameters
    const char *p_hex = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F";
    const char *a_hex = "0000000000000000000000000000000000000000000000000000000000000000";
    const char *b_hex = "0000000000000000000000000000000000000000000000000000000000000007";
    const char *order_hex = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";

    // Define the test points
    const char *x1_hex = "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
    const char *y1_hex = "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8";
    const char *x2_hex = "C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5";
    const char *y2_hex = "1AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A";

    BN_CTX *ctx = BN_CTX_new();
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp256k1);

    BIGNUM *p = BN_new();
    BIGNUM *a = BN_new();
    BIGNUM *b = BN_new();
    BIGNUM *order = BN_new();
    BIGNUM *x1 = BN_new();
    BIGNUM *y1 = BN_new();
    BIGNUM *x2 = BN_new();
    BIGNUM *y2 = BN_new();

    BN_hex2bn(&p, p_hex);
    BN_hex2bn(&a, a_hex);
    BN_hex2bn(&b, b_hex);
    BN_hex2bn(&order, order_hex);
    BN_hex2bn(&x1, x1_hex);
    BN_hex2bn(&y1, y1_hex);
    BN_hex2bn(&x2, x2_hex);
    BN_hex2bn(&y2, y2_hex);

    EC_POINT *p1 = EC_POINT_new(group);
    EC_POINT *p2 = EC_POINT_new(group);
    EC_POINT *result = EC_POINT_new(group);

    EC_POINT_set_affine_coordinates(group, p1, x1, y1, ctx);
    EC_POINT_set_affine_coordinates(group, p2, x2, y2, ctx);

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
    EC_POINT_get_affine_coordinates(group, result, x_result, y_result, ctx);

    // Print the result
    print_bn("<< result->x:", x_result);
    print_bn("<< result->y:", y_result);

    printf("\n### OpenSSL\n");
    printf("Point Addition Test:\n");
    printf("P1 + P2 = (\n    0x%s\n    , \n    0x%s\n    )\n", 
           BN_bn2hex(x_result), BN_bn2hex(y_result));

    // Free the allocated memory
    BN_free(p);
    BN_free(a);
    BN_free(b);
    BN_free(order);
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

    return 0;
}
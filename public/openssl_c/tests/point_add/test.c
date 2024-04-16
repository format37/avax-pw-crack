#include <stdio.h>
#include <openssl/ec.h>
#include <openssl/bn.h>

int main() {
    // Define the secp256k1 curve parameters
    const char *p_hex = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F";
    const char *a_hex = "0000000000000000000000000000000000000000000000000000000000000000";
    const char *b_hex = "0000000000000000000000000000000000000000000000000000000000000007";
    const char *x_hex = "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
    const char *y_hex = "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8";
    const char *order_hex = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";

    BN_CTX *ctx = BN_CTX_new();
    EC_GROUP *group = EC_GROUP_new(EC_GFp_mont_method());

    BIGNUM *p = BN_new();
    BIGNUM *a = BN_new();
    BIGNUM *b = BN_new();
    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();
    BIGNUM *order = BN_new();

    BN_hex2bn(&p, p_hex);
    BN_hex2bn(&a, a_hex);
    BN_hex2bn(&b, b_hex);
    BN_hex2bn(&x, x_hex);
    BN_hex2bn(&y, y_hex);
    BN_hex2bn(&order, order_hex);

    EC_GROUP_set_curve_GFp(group, p, a, b, ctx);
    EC_GROUP_set_generator(group, EC_POINT_new(group), order, BN_value_one());

    EC_POINT *p1 = EC_POINT_new(group);
    EC_POINT *p2 = EC_POINT_new(group);
    EC_POINT *sum = EC_POINT_new(group);

    EC_POINT_set_affine_coordinates(group, p1, x, y, ctx);

    // Initialize p2 with sample values
    BIGNUM *x2 = BN_new();
    BIGNUM *y2 = BN_new();
    BN_hex2bn(&x2, "C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5");
    BN_hex2bn(&y2, "1AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A");
    EC_POINT_set_affine_coordinates(group, p2, x2, y2, ctx);

    // Perform point addition
    EC_POINT_add(group, sum, p1, p2, ctx);

    // Retrieve the result
    BIGNUM *x_sum = BN_new();
    BIGNUM *y_sum = BN_new();
    EC_POINT_get_affine_coordinates(group, sum, x_sum, y_sum, ctx);

    // Print the result
    char *x_str = BN_bn2hex(x_sum);
    char *y_str = BN_bn2hex(y_sum);
    printf("Sum: (%s, %s)\n", x_str, y_str);

    // Free the allocated memory
    OPENSSL_free(x_str);
    OPENSSL_free(y_str);
    BN_free(x_sum);
    BN_free(y_sum);
    BN_free(x2);
    BN_free(y2);
    BN_free(p);
    BN_free(a);
    BN_free(b);
    BN_free(x);
    BN_free(y);
    BN_free(order);
    EC_POINT_free(p1);
    EC_POINT_free(p2);
    EC_POINT_free(sum);
    BN_CTX_free(ctx);
    EC_GROUP_free(group);

    return 0;
}
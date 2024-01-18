#include <stdio.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>

void print_bn(const char* label, const BIGNUM* bn) {
    char* bn_str = BN_bn2hex(bn);
    printf("%s: %s\n", label, bn_str);
    OPENSSL_free(bn_str);
}

int main() {
    BN_CTX *ctx = BN_CTX_new();
    OPENSSL_assert(ctx != NULL);

    char* test_values_a[] = {
        "1", 
        "F", 
        "FF", 
        "ABC", 
        "1234567890ABCDEF", 
        "10", 
        "FFFFFFFFFFFFFFFFF",
        "1234567890ABCDEFFEDCBA0987654321"
    };

    char* test_values_b[] = {
        "2", 
        "F", 
        "101", 
        "10", 
        "FEDCBA0987654321", 
        "10", 
        "10000000000000000",
        "1234567890ABCDEFFEDCBA0987654321"
    };

    int num_tests = sizeof(test_values_a) / sizeof(test_values_a[0]);

    for (int test = 0; test < num_tests; ++test) {
        printf("\nTest %d:\n", test + 1);
        BIGNUM *a = BN_new();
        BIGNUM *b = BN_new();
        BIGNUM *result = BN_new();

        BN_hex2bn(&a, test_values_a[test]);
        BN_hex2bn(&b, test_values_b[test]);
        if (test==7) {
            //BN_set_negative(a, 1);
            BN_set_negative(b, 1);
        }
        BN_mul(result, a, b, ctx);
        print_bn("a", a);
        print_bn("b", b);
        print_bn("a * b", result);

        BN_free(a);
        BN_free(b);
        BN_free(result);
    }

    BN_CTX_free(ctx);
    return 0;
}
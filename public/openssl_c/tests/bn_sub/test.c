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

    // New test values for subtraction
    char* test_values_a[] = {
        "1", 
        "DEF", 
        "10000", 
        "1234567890ABCDEF", 
        "123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0", 
        "FFFFFFFFFFFFFFFF",
        "1234567890ABCDEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    };

    char* test_values_b[] = {
        "0", 
        "ABC", 
        "F", 
        "1000000000000000", 
        "111111111111111100000000000000000000000000000000", 
        "FFFFFFFFFFFFFFFE",
        "10000000000000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    };

    int num_tests = sizeof(test_values_a) / sizeof(test_values_a[0]);

    for (int test = 0; test < num_tests; ++test) {
        BIGNUM *a = BN_new();
        BIGNUM *b = BN_new();
        BIGNUM *result = BN_new();

        BN_hex2bn(&a, test_values_a[test]);
        BN_hex2bn(&b, test_values_b[test]);

        // Test subtraction (a - b)
        if(!BN_sub(result, a, b)) {
            fprintf(stderr, "Subtraction failed for test case %d\\n", test + 1);
        }

        printf("\nTest %d:\n", test + 1);
        print_bn("a", a);
        print_bn("b", b);
        print_bn("a - b", result);

        BN_free(a);
        BN_free(b);
        BN_free(result);
    }

    BN_CTX_free(ctx);
    return 0;
}
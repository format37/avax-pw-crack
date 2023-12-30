#include <stdio.h>
#include <openssl/bn.h>
#include <openssl/err.h>

void print_bn(const char* label, const BIGNUM* bn) {
    if (bn) {
        char* bn_str = BN_bn2hex(bn);
        printf("%s: %s\n", label, bn_str);
        OPENSSL_free(bn_str);
    } else {
        printf("%s: (null)\n", label);
    }
}

int main() {
    BN_CTX *ctx = BN_CTX_new();
    if (ctx == NULL) {
        fprintf(stderr, "Error: BN_CTX_new() failed.\n");
        return 1;
    }

    // Prepare test values for 'a' and 'b' for GCD calculation
    const char* test_values_a[] = {
        "123456789ABCDEF",
        "1FFF3",
        "FEDCBA9876543210"
    };

    const char* test_values_b[] = {
        "FEDCBA987654321",
        "2468ACE",
        "FEDCBA9876543210"
    };

    int num_tests = sizeof(test_values_a) / sizeof(test_values_a[0]);

    for (int test = 0; test < num_tests; ++test) {
        BIGNUM *a = BN_new();
        BIGNUM *b = BN_new();
        BIGNUM *gcd = BN_new();

        if (a == NULL || b == NULL || gcd == NULL) {
            fprintf(stderr, "Error allocating BIGNUMs.\n");
            // Cleanup before exiting
            BN_free(a);
            BN_free(b);
            BN_free(gcd);
            BN_CTX_free(ctx);
            return 1;
        }

        BN_hex2bn(&a, test_values_a[test]);
        BN_hex2bn(&b, test_values_b[test]);

        if (!BN_gcd(gcd, a, b, ctx)) {
            fprintf(stderr, "Error computing GCD.\n");
            ERR_print_errors_fp(stderr);
        } else {
            printf("Test %d:\n", test + 1);
            print_bn("a", a);
            print_bn("b", b);
            print_bn("gcd", gcd);
        }

        BN_free(a);
        BN_free(b);
        BN_free(gcd);
    }

    BN_CTX_free(ctx);
    return 0;
}
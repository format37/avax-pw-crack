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

    const char* test_values_a[] = {
        "123456789ABCDEF",   // arbitrary value
        "1FFF3",             // arbitrary value
        "10001",             // arbitrary value, less than the prime 'n' below
        "10001"             // arbitrary value
    };

    // Using a prime number for n ensures that any a that's not a multiple of n will be coprime to n
    const char* test_values_n[] = {
        "FEDCBA987654323",   // prime number
        "100000000000003",   // prime number
        "10000000000000000000000000000000000000000000000000000000000000461", // prime number
        "FFFFFFFFFFFFFFFF"    // prime number (it's FFFF FFFF FFFF FFFF)
    };

    // Number of tests defined by the number of elements in test_values_a/n arrays.
    int num_tests = sizeof(test_values_a) / sizeof(test_values_a[0]);

    for (int test = 0; test < num_tests; ++test) {
        BIGNUM *a = BN_new();
        BIGNUM *n = BN_new();
        BIGNUM *mod_inverse = NULL;

        if (a == NULL || n == NULL) {
            fprintf(stderr, "Error allocating BIGNUMs.\n");
            // Cleanup before exiting
            BN_free(a);
            BN_free(n);
            BN_CTX_free(ctx);
            return 1;
        }

        BN_hex2bn(&a, test_values_a[test]);
        BN_hex2bn(&n, test_values_n[test]);

        mod_inverse = BN_mod_inverse(NULL, a, n, ctx);
        if (mod_inverse == NULL) {
            unsigned long err_code = ERR_get_error();  // Get the error code
            if (ERR_GET_REASON(err_code) == BN_R_NO_INVERSE) {
                printf("Test %d:\n", test + 1);
                print_bn("a", a);
                print_bn("n", n);
                printf("No modular inverse exists for the given 'a' and 'n'.\n");
            } else {
                fprintf(stderr, "Error computing modular inverse.\n");
                ERR_print_errors_fp(stderr);
            }
        } else {
            printf("Test %d:\n", test + 1);
            print_bn("a", a);
            print_bn("n", n);
            print_bn("modular inverse", mod_inverse);
        }

        BN_free(a);
        BN_free(n);
        BN_free(mod_inverse); // mod_inverse is created by BN_mod_inverse
    }

    BN_CTX_free(ctx);
    return 0;
}
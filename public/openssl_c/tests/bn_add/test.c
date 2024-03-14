#include <stdio.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <string.h>

#define MAX_BIGNUM_WORDS 4     // For 256-bit numbers

void print_bn(const char* label, const BIGNUM* bn) {
    char *str = BN_bn2hex(bn);
    printf("%s: %s\n", label, str);
    OPENSSL_free(str);
}

int main() {
    BN_CTX *ctx = BN_CTX_new();
    OPENSSL_assert(ctx != NULL);

    BN_ULONG test_values_a[][MAX_BIGNUM_WORDS] = {
        {0xffffffffffffffff, 0xffffffffffffffff, 0,0}, // 0
        {0,0,0,0x1}, // 1
        {0xffffffffffffffff, 0,0,0}, // 2
        {0xffffffffffffffff, 0xffffffffffffffff, 0,0}, // 3
        {0x1234567890abcdef, 0,0,0}, // 4
        {0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff}, // 5
        {0x1234567890abcdef, 0,0,0}, // 6
        {0x1234567890abcdef, 0,0,0}, // 7
        {0x1234567890abcdef, 0,0,0}, // 8
        {0x1234567890abcdef, 0,0,0}  // 9
    };

    BN_ULONG test_values_b[][MAX_BIGNUM_WORDS] = {
        {0x1, 0,0,0}, // 0
        {0,0,0,0x2}, // 1
        {0x1, 0,0,0}, // 2
        {0x1, 0,0,0}, // 3
        {0,0,0,0}, // 4
        {0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff}, // 5
        {0x5678901234567890, 0,0,0}, // 6
        {0x5678901234567890, 0,0,0}, // 7
        {0xfedcba0987654321, 0,0,0}, // 8
        {0xfedcba0987654321, 0,0,0}  // 9
    };

    // Set sign to 0 for positive numbers, 1 for negative numbers
    int sign_a[] = {0, 0, 0, 0, 0, 0, 0, 1, 0, 0};
    int sign_b[] = {0, 0, 0, 0, 0, 0, 0, 1, 0, 1};

    int num_tests = sizeof(test_values_a) / sizeof(test_values_a[0]);
    for (int test = 0; test < num_tests; ++test) {
        BIGNUM *a = BN_new();
        BIGNUM *b = BN_new();
        BIGNUM *result = BN_new();

        BN_set_word(a, test_values_a[test][MAX_BIGNUM_WORDS - 1]);
        BN_set_word(b, test_values_b[test][MAX_BIGNUM_WORDS - 1]);

        for (int i = MAX_BIGNUM_WORDS - 2; i >= 0; --i) {
            BN_lshift(a, a, 64);
            BN_lshift(b, b, 64);
            BN_add_word(a, test_values_a[test][i]);
            BN_add_word(b, test_values_b[test][i]);
        }

        // Set the sign of the numbers
        BN_set_negative(a, sign_a[test]);
        BN_set_negative(b, sign_b[test]);

        // Test addition (a + b)
        if(!BN_add(result, a, b)) {
            fprintf(stderr, "Addition failed for test case %d\n", test + 1);
        }

        printf("\nTest %d:\n", test);
        print_bn("a: ", a);
        print_bn("b: ", b);
        print_bn("result: ", result);

        BN_free(a);
        BN_free(b);
        BN_free(result);
    }

    BN_CTX_free(ctx);
    return 0;
}
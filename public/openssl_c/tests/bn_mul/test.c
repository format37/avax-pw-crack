//bn_div_openssl_test.c
#include <stdio.h>
#include <openssl/bn.h>

#define TEST_BIGNUM_WORDS 4

void print_bn(const char* label, const BIGNUM* bn) {
    char* bn_str = BN_bn2hex(bn);
    int i = 0;
    while (bn_str[i] == '0' && bn_str[i+1] != '\0') {
        i++;
    }
    printf("%s: %s\n", label, &bn_str[i]);
    OPENSSL_free(bn_str);
}

void set_bignum_words(BIGNUM *bn, const BN_ULONG *words, int num_words) {
    BN_zero(bn);
    for (int i = 0; i < num_words; ++i) {
        BN_add_word(bn, words[i]);
        if (i < num_words - 1) {
            BN_lshift(bn, bn, BN_BITS2);
        }
    }
}

int main() {
    BN_CTX *ctx = BN_CTX_new();

    BN_ULONG test_values_a[][TEST_BIGNUM_WORDS] = {
        {0xd2a68e877f99fed4, 0x4620881d385be245, 0xfade7e1c8be17cc7, 0x871c611855bf0ca1},
    };

    BN_ULONG test_values_b[][TEST_BIGNUM_WORDS] = {
        {0xac946f7cd9ccebb8, 0xd59803e73c7d12aa, 0x395b2eb7e59a8ba1, 0x19742df442fc6604},
    };

    // 0 for positive, 1 for negative
    int sign_a[] = {0};
    int sign_b[] = {0};

    int num_tests = sizeof(test_values_a) / sizeof(test_values_a[0]);

    for (int test = 0; test < num_tests; ++test) {
        printf("\nTest %d:\n", test);
        BIGNUM *a = BN_new();
        BIGNUM *b = BN_new();
        BIGNUM *result = BN_new();

        set_bignum_words(a, test_values_a[test], TEST_BIGNUM_WORDS);
        set_bignum_words(b, test_values_b[test], TEST_BIGNUM_WORDS);

        // Set signs
        if (sign_a[test]) BN_set_negative(a, 1);
        if (sign_b[test]) BN_set_negative(b, 1);

        print_bn("a", a);
        print_bn("b", b);

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
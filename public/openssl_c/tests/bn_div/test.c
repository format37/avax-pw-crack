//bn_div_openssl_test.c
#include <stdio.h>
#include <openssl/bn.h>

#define MAX_BIGNUM_WORDS 4

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

    BN_ULONG test_values_dividend[][MAX_BIGNUM_WORDS] = {
        {0xffffffffffffffff, 0xffffffffffffffe, 0xbaaedce6af48a03b, 0xbfd25e8cd0364141},
    };

    BN_ULONG test_values_divisor[][MAX_BIGNUM_WORDS] = {
        {0x1b2db4c027cdbaba, 0x70116675aa53aa8a, 0xad1c289591e564d3, 0xcaa5c571ffccab5a},
    };

    int num_tests = sizeof(test_values_dividend) / sizeof(test_values_dividend[0]);

    for (int test = 0; test < num_tests; ++test) {
        printf("\nTest %d:\n", test);
        BIGNUM *dividend = BN_new();
        BIGNUM *divisor = BN_new();
        BIGNUM *quotient = BN_new();
        BIGNUM *remainder = BN_new();

        set_bignum_words(dividend, test_values_dividend[test], MAX_BIGNUM_WORDS);
        set_bignum_words(divisor, test_values_divisor[test], MAX_BIGNUM_WORDS);

        BN_div(quotient, remainder, dividend, divisor, ctx);

        print_bn("Dividend", dividend);
        print_bn("Divisor", divisor);
        print_bn("Quotient", quotient);
        print_bn("Remainder", remainder);

        // dividend
        // -------- = quotient, remainder
        // divisor
        // Multiplication back: quotient * divisor + remainder = dividend
        BIGNUM *product = BN_new();
        BN_mul(product, quotient, divisor, ctx);
        // Print the product
        print_bn("Product", product);
        // Add the remainder
        BN_add(product, product, remainder);
        // Print the dividend
        print_bn("Product + Remainder", product);

        BN_free(dividend);
        BN_free(divisor);
        BN_free(quotient);
        BN_free(remainder);
    }

    BN_CTX_free(ctx);
    return 0;
}
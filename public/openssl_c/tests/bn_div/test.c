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
        {0,0,0,0xB}, // 0: Simple division
        {0x1,0,0,0}, // 1: Division by 1
        {0,0,0x1234567890ABCDEF,0x7234567890ABCDEF}, // 2: Large numbers
        {0x1,0,0,0}, // 3: Dividend smaller than divisor
        {0xFFFFFFFFFFFFFFFF,0xFFFFFFFFFFFFFFFF,0xFFFFFFFFFFFFFFFF,0xFFFFFFFFFFFFFFFF}, // 4: Maximum positive value
        {0x1,0,0,0x8000000000000000}, // 5: Negative dividend
        {0,0,0x1,0x8000000000000000}, // 6: Negative divisor
        {0x1,0,0,0x8000000000000000}, // 7: Both negative
        {0,0,0x1,0}, // 8: Multiple 16-sign words
        {0,0,0xFFFFFFFFFFFFFFFF,0}, // 9: Numerical order transition
        {0,0,0x1234567890ABCDEF,0x7234567890ABCDEF}, // 10: Large dividend, small divisor
        {0,0,0x1,0x7234567890ABCDEF}, // 11: Small dividend, large divisor
        {0,0,0,0}, // 12: Zero dividend
        {0x1234567890ABCDEF,0x7234567890ABCDEF,0x1234567890ABCDEF,0x7234567890ABCDEF}, // 13: Four-word dividend and divisor
        {0xFFFFFFFFFFFFFFFF,0,0,0}, // 14: Two-word dividend with maximum value in the first word
        {0,0xFFFFFFFFFFFFFFFF,0,0}, // 15: Two-word dividend with maximum value in the second word
    };

    BN_ULONG test_values_divisor[][MAX_BIGNUM_WORDS] = {
        {0,0,0,0x3}, // 0: Simple divisor
        {0x1,0,0,0}, // 1: Division by 1
        {0,0,0x2,0}, // 2: Large divisor
        {0,0,0x100,0}, // 3: Divisor larger than dividend
        {0x2,0,0,0}, // 4: Small divisor
        {0x2,0,0,0}, // 5: Positive divisor
        {0,0,0x1,0}, // 6: Negative divisor
        {0,0,0x1,0x8000000000000000}, // 7: Both negative
        {0,0,0x10,0}, // 8: Multiple 16-sign words in divisor
        {0,0,0x1,0}, // 9: Numerical order transition in divisor
        {0,0,0,0x1}, // 10: Small divisor
        {0,0,0x1234567890ABCDEF,0}, // 11: Large divisor
        {0,0,0,0x1}, // 12: Non-zero divisor for zero dividend
        {0x1234567890ABCDEF,0,0,0}, // 13: One-word divisor
        {0x100,0,0,0}, // 14: Divisor smaller than the first word of the dividend
        {0,0x100,0,0}, // 15: Divisor smaller than the second word of the dividend
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

        BN_free(dividend);
        BN_free(divisor);
        BN_free(quotient);
        BN_free(remainder);
    }

    BN_CTX_free(ctx);
    return 0;
}
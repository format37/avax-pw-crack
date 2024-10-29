//bn_div_openssl_test.c
#include <stdio.h>
#include <openssl/bn.h>

#define TEST_BIGNUM_WORDS 10

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

    BN_ULONG test_values_dividend[][TEST_BIGNUM_WORDS] = {
        // {0x8e020bca63c2d3b4, 0xf15d956d1119704c, 0x793bbdfa2cbe57d7, 0x51a13724b434b483, 0xda8f4665b027f674, 0xfab37c1f434754f2, 0x9352e2c1b6dc753e, 0x0675365166805884},
        // {0xa9d76a4234a8ded, 0x7af964ec3f6f871b, 0xe09d7f67cc580732, 0x3b11b98c6222abbb, 0x0bdfd291448c33e6, 0xa46834fe88684cf0, 0x5106877163ee71eb, 0x5186b6de04720283},
        // {
        //     0x0,
        //     0x0,
        //     0x0,
        //     0x0,
        //     0x0,
        //     0x0,
        //     0x0,
        //     0x0,
        //     0x72b47b314e91753a,
        //     0x3f38e8c61b9ed846
        // }
        //{0, 0, 0xfffffffffffffffe, 0xffffffffffffffff, 1, 0, 0, 0, 0, 0} // 1 ffffffffffffffff fffffffffffffffe 0000000000000000 0000000000000000
        {0, 0, 0, 0, 0, 1, 0xffffffffffffffff, 0xfffffffffffffffe, 0, 0} // 1 ffffffffffffffff fffffffffffffffe 0000000000000000 0000000000000000
    };

    BN_ULONG test_values_divisor[][TEST_BIGNUM_WORDS] = {
        // {0, 0, 0, 0, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xfffffffefffffc2f},
        // {0, 0, 0, 0, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xfffffffefffffc2f},
        // {
        //     0x0,
        //     0x0,
        //     0x0,
        //     0x0,
        //     0x0,
        //     0x0,
        //     0x0,
        //     0x0,
        //     0xd1075ad5b373c6d,
        //     0x1dfd6bc539e3e809
        // }
        {0, 0, 0, 0, 0, 0, 0, 1, 0, 1} // 1 0000000000000000 0000000000000001
    };

    // 0 for positive, 1 for negative
    int sign_dividend[] = {0};
    int sign_divisor[] = {0};

    int num_tests = sizeof(test_values_dividend) / sizeof(test_values_dividend[0]);

    for (int test = 0; test < num_tests; ++test) {
        printf("\nTest %d:\n", test);
        BIGNUM *dividend = BN_new();
        BIGNUM *divisor = BN_new();
        BIGNUM *quotient = BN_new();
        BIGNUM *remainder = BN_new();

        set_bignum_words(dividend, test_values_dividend[test], TEST_BIGNUM_WORDS);
        set_bignum_words(divisor, test_values_divisor[test], TEST_BIGNUM_WORDS);

        // Set signs
        if (sign_dividend[test]) BN_set_negative(dividend, 1);
        if (sign_divisor[test]) BN_set_negative(divisor, 1);

        print_bn("Dividend", dividend);
        print_bn("Divisor", divisor);

        BN_div(quotient, remainder, dividend, divisor, ctx);

        print_bn("Quotient", quotient);
        print_bn("Remainder", remainder);

        // dividend
        // -------- = quotient, remainder
        // divisor
        // Multiplication back: quotient * divisor + remainder = dividend
        // BIGNUM *product = BN_new();
        // BN_mul(product, quotient, divisor, ctx);
        // // Print the product
        // print_bn("Product", product);
        // // Add the remainder
        // BN_add(product, product, remainder);
        // // Print the dividend
        // print_bn("Product + Remainder", product);

        BN_free(dividend);
        BN_free(divisor);
        BN_free(quotient);
        BN_free(remainder);
        break;
    }

    BN_CTX_free(ctx);
    return 0;
}
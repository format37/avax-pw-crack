#include <stdio.h>
#include <openssl/bn.h>

void print_bn(const char* label, const BIGNUM* bn) {
    char* bn_str = BN_bn2hex(bn);
    printf("%s: %s\n", label, bn_str);
    OPENSSL_free(bn_str);
}

int main() {
    BN_CTX *ctx = BN_CTX_new();

    // Expanded Test values for 'dividend' and 'divisor' with leading zero words
    char* test_values_dividend[] = {
        "1",
        "F",
        "F",
        "17", // 23 in decimal
        "1234567890ABCDEF", // Single-word dividend
        "000000001234567890ABCDEF", // Leading zero words
        "0000000000000000000000001234567890ABCDEF" // More leading zero words
    };

    char* test_values_divisor[] = {
        "2",
        "F",
        "1",
        "5", // 5 in decimal
        "1", // Single-word divisor
        "000000000000000000000001", // Leading zero words
        "0000000000000000000000000000000000000001" // More leading zero words
    };

    int num_tests = sizeof(test_values_dividend) / sizeof(test_values_dividend[0]);

    for (int test = 0; test < num_tests; ++test) {
        BIGNUM *dividend = BN_new();
        BIGNUM *divisor = BN_new();
        BIGNUM *quotient = BN_new();
        BIGNUM *remainder = BN_new();

        BN_hex2bn(&dividend, test_values_dividend[test]);
        BN_hex2bn(&divisor, test_values_divisor[test]);

        // For the multi-word test, manually set the higher word of the dividend
        if (test >= 4) {
            BIGNUM *high_word = BN_new();
            BN_hex2bn(&high_word, "FEDCBA0987654321");
            BN_lshift(high_word, high_word, 64); // Shift left by 64 bits
            BN_add(dividend, dividend, high_word); // Add to the original dividend
            BN_free(high_word);
        }

        BN_div(quotient, remainder, dividend, divisor, ctx);

        printf("Test %d:\n", test + 1);
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

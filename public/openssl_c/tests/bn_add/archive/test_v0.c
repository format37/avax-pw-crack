#include <stdio.h>
#include <openssl/bn.h>

void print_bn(const char* label, const BIGNUM* bn) {
    char* bn_str = BN_bn2hex(bn);
    printf("%s: %s\n", label, bn_str);
    OPENSSL_free(bn_str);
}

int main() {
    BN_CTX *ctx = BN_CTX_new();

    // Test values for 'dividend' and 'divisor'
    char* test_values_dividend[] = {
        "1",
        "F",
        "F",
        "17", // 23 in decimal
        "1234567890ABCDEF" // Single-word dividend
    };

    char* test_values_divisor[] = {
        "2",
        "F",
        "1",
        "5", // 5 in decimal
        "1" // Single-word divisor
    };

    // Set the maximum number of test cases
    int num_tests = 5;

    // Initialize 'dividend' and 'divisor' with test values for each test
    for (int test = 0; test < num_tests; ++test) {
        BIGNUM *dividend = BN_new();
        BIGNUM *divisor = BN_new();
        BIGNUM *quotient = BN_new();
        BIGNUM *remainder = BN_new();

        // Convert test values from hex strings to BIGNUM
        BN_hex2bn(&dividend, test_values_dividend[test]);
        BN_hex2bn(&divisor, test_values_divisor[test]);

        // Perform division
        BN_div(quotient, remainder, dividend, divisor, ctx);

        // Print results
        printf("Test %d:\n", test + 1);
        print_bn("Dividend", dividend);
        print_bn("Divisor", divisor);
        print_bn("Quotient", quotient);
        print_bn("Remainder", remainder);

        // Free BIGNUMs
        BN_free(dividend);
        BN_free(divisor);
        BN_free(quotient);
        BN_free(remainder);
    }

    BN_CTX_free(ctx);
    return 0;
}

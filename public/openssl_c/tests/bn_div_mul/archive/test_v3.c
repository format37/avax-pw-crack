#include <stdio.h>
#include <openssl/bn.h>

void print_bn(const char* label, const BIGNUM* bn) {
    char* bn_str = BN_bn2hex(bn);
    printf("%s: %s\n", label, bn_str);
    OPENSSL_free(bn_str);
}

int main() {
    BN_CTX *ctx = BN_CTX_new();

    // Expanded Test values for 'dividend' and 'divisor' with accurate multi-word representation
    char* test_values_dividend[] = {
        "000000000000000000000000000000000000000000000000000000000000000B", // 0
        "0000000000000001000000000000000000000000000000000000000000000000", // 1
        "000000000000000000000000000000001234567890ABCDEF7234567890ABCDEF", // 2
        "0000000000000001000000000000000000000000000000000000000000000000", // 3
    };
        /*"F", // 2
        "F", // 3
        "17", // 4
        "1234567890ABCDEF", // 5
        "1234567890ABCDEF7234567890ABCDEF",  // 6        
        "10000000000000005", // 7*/

    char* test_values_divisor[] = {
        "0000000000000000000000000000000000000000000000000000000000000003", // 0
        "0000000000000002000000000000000000000000000000000000000000000000", // 1
        "0000000000000000000000000000000000000000000000020000000000000000", // 2
        "0000000000000000000000000000000000000000000001000000000000000000", // 3
    };
        /*"F", // 2
        "1", // 3
        "5", // 4 
        "1", // 5
        "2",  // 6
        "2", // 1*/

    int num_tests = sizeof(test_values_dividend) / sizeof(test_values_dividend[0]);

    for (int test = 0; test < num_tests; ++test) {
        printf("\nTest %d:\n", test);
        BIGNUM *dividend = BN_new();
        BIGNUM *divisor = BN_new();
        BIGNUM *quotient = BN_new();
        BIGNUM *remainder = BN_new();

        BN_hex2bn(&dividend, test_values_dividend[test]);
        BN_hex2bn(&divisor, test_values_divisor[test]);

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

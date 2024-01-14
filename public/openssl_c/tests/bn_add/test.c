#include <stdio.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>

void print_bn(const char* label, const BIGNUM* bn) {
    char *str = BN_bn2hex(bn);
    printf("%s: %s\n", label, str);
    OPENSSL_free(str);
}

int main() {
    BN_CTX *ctx = BN_CTX_new();
    OPENSSL_assert(ctx != NULL);

    // Define test values for 'a' and 'b' corresponding to your CUDA test cases
    /*char* test_values_a[] = {
        "1",
        "FFFFFFFFFFFFFFFF",
        "10000000000000000",
        "FFFFFFFFFFFFFFFF0000000000000000", // test 4
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", // test 5: -1 in two's complement (two words)
        "-FFFFFFFFFFFFFFFF0000000000000001", // test 6: Negative number with two words
        "1" // test 7
    };

    char* test_values_b[] = {
        "2",
        "1",
        "20000000000000000",
        "1FFFFFFFFFFFFFFFF", // test 4
        "-1", // test 5
        "FFFFFFFFFFFFFFFF", // test 6
        "-FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE" // test 7: -2 in two's complement (two words)
    };*/
    char* test_values_a[] = {
        "A",    // 10
        "A",    // 10
        "F",    // 15
        "-A",   // -10
        "-A",   // -10
        "-A"    // -10
    };

    char* test_values_b[] = {
        "-5",   // -5
        "-A",   // -10
        "A",    // 10
        "-5",   // -5
        "5",    // 5
        "F"     // 15
    };

    int num_tests = sizeof(test_values_a) / sizeof(test_values_a[0]);

    for (int test = 0; test < num_tests; ++test) {
        BIGNUM *a = BN_new();
        BIGNUM *b = BN_new();
        BIGNUM *result = BN_new();

        BN_hex2bn(&a, test_values_a[test]);
        BN_hex2bn(&b, test_values_b[test]);

        // Test addition (a + b)
        if(!BN_add(result, a, b)) {
            fprintf(stderr, "Addition failed for test case %d\n", test + 1);
        }

        printf("\nTest %d:\n", test + 1);
        print_bn("a     : ", a);
        print_bn("b     : ", b);
        print_bn("result: ", result);

        BN_free(a);
        BN_free(b);
        BN_free(result);
    }

    BN_CTX_free(ctx);
    return 0;
}

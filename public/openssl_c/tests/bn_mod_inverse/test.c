#include <stdio.h>
#include <openssl/bn.h>
#include <openssl/err.h>

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
    printf("++ Starting BN_mod_inverse test ++\n");
    BN_CTX *ctx = BN_CTX_new();
    
    BN_ULONG test_values_a[][MAX_BIGNUM_WORDS] = {
        {0,0,0,0x3},     // 0: a = 3, n = 11
        {0,0,0,0x2A},    // 1: a = 42, n = 2017
        {0,0,0,0x4D2},   // 2: a = 1234, n = 5678
        {0,0,0,0x0},     // 3: a = 0, n = 11
        {0,0,0,0x1},     // 4: a = 1, n = 11
        {0,0,0,0xA},     // 5: a = 10, n = 11
        {0,0,0,0xB},     // 6: a = 11, n = 11
        {0,0,0,0x3},     // 7: a = 3, n = 1
        {0,0,0,0x3},     // 8: a = 3, n = 2
        {0,0,0,0x3},     // 9: a = 3, n = 11 (for negative 'a' test case)
        {0,0,0,0x3},     // 10: a = 3, n = 11 (for negative 'n' test case)
        {0,0,0,0x3},     // 11: a = 3, n = 11 (for negative 'a' and 'n' test case)
        {0,0,0,0x2A},    // 12: a = 42, n = 2017 (for negative 'a' test case)
        {0,0,0,0x4D2},   // 13: a = 1234, n = 5678 (for negative 'n' test case)
        {0,0x11F71B54,0x92EA6E0,0},    // 14: a = 1234567890, n = 9876543210
        {0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF},    // 15: a = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF, n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
        {0,0,0,0x4},     // 16: a = 4, n = 12
        {0,0,0,0x6},     // 17: a = 6, n = 15
        {0,0,0,0x12},    // 18: a = 18, n = 24
        {0xffffffffffffffff, 0xffffffffffffffe, 0xbaaedce6af48a03b, 0xbfd25e8cd0364141},
        {0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xfffffffefffffc2f},

    };

    BN_ULONG test_values_n[][MAX_BIGNUM_WORDS] = {
        {0,0,0,0xB},     // 0: a = 3, n = 11
        {0,0,0,0x7E1},   // 1: a = 42, n = 2017
        {0,0,0,0x162E},  // 2: a = 1234, n = 5678
        {0,0,0,0xB},     // 3: a = 0, n = 11
        {0,0,0,0xB},     // 4: a = 1, n = 11
        {0,0,0,0xB},     // 5: a = 10, n = 11
        {0,0,0,0xB},     // 6: a = 11, n = 11
        {0,0,0,0x1},     // 7: a = 3, n = 1
        {0,0,0,0x2},     // 8: a = 3, n = 2
        {0,0,0,0xB},     // 9: a = 3, n = 11 (for negative 'a' test case)
        {0,0,0,0xB},     // 10: a = 3, n = 11 (for negative 'n' test case)
        {0,0,0,0xB},     // 11: a = 3, n = 11 (for negative 'a' and 'n' test case)
        {0,0,0,0x7E1},   // 12: a = 42, n = 2017 (for negative 'a' test case)
        {0,0,0,0x162E},  // 13: a = 1234, n = 5678 (for negative 'n' test case)
        {0,0x2456AF20,0x962E90,0},    // 14: a = 1234567890, n = 9876543210
        {0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF},    // 15: a = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF, n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
        {0,0,0,0xC},     // 16: a = 4, n = 12
        {0,0,0,0xF},     // 17: a = 6, n = 15
        {0,0,0,0x18},    // 18: a = 18, n = 24
        {0x1b2db4c027cdbaba, 0x70116675aa53aa8a, 0xad1c289591e564d3, 0xcaa5c571ffccab5a},
        {0x4c4619154810c1c0, 0xdaa4ddd8c73971d1, 0x59db91705f2113ce, 0x51b9885e4578874d},
    };

    // 0 for positive, 1 for negative
    int sign_a[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0,0};
    int sign_n[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0,0};

    // Number of tests defined by the number of elements in test_values_a/n arrays.
    int num_tests = sizeof(test_values_a) / sizeof(test_values_a[0]);

    //for (int test = 0; test < num_tests; ++test) {
    for (int i = 0; i < num_tests; ++i) {
        printf("Test %d:\n", i);
        BIGNUM *a = BN_new();
        BIGNUM *n = BN_new();
        BIGNUM *mod_inverse = NULL;

        set_bignum_words(a, test_values_a[i], MAX_BIGNUM_WORDS);
        set_bignum_words(n, test_values_n[i], MAX_BIGNUM_WORDS);

        // Set signs
        //if (sign_a[i]) BN_set_negative(a, 1);
        //if (sign_n[i]) BN_set_negative(n, 1);

        print_bn("a", a);
        print_bn("n", n);

        mod_inverse = BN_mod_inverse(NULL, a, n, ctx);

        if (mod_inverse == NULL) {
            unsigned long err_code = ERR_get_error();  // Get the error code
            if (ERR_GET_REASON(err_code) == BN_R_NO_INVERSE) {
                printf("[%d] No modular inverse exists for the given 'a' and 'n'.\n", i);
            } else {
                fprintf(stderr, "Error computing modular inverse.\n");
                ERR_print_errors_fp(stderr);
            }
        } else {
            printf("[%d] ", i);
            print_bn("Modular inverse", mod_inverse);
        }
        printf("\n");

        BN_free(a);
        BN_free(n);
        BN_free(mod_inverse); // mod_inverse is created by BN_mod_inverse
        //break;
    }

    BN_CTX_free(ctx);
    return 0;
}
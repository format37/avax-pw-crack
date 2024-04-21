#include <stdio.h>
#include <openssl/bn.h>
#include <openssl/err.h>

#define MAX_BIGNUM_WORDS 4

void reverse_order(BN_ULONG test_values_a[][MAX_BIGNUM_WORDS], BN_ULONG test_values_b[][MAX_BIGNUM_WORDS], size_t num_rows) {
    for (size_t i = 0; i < num_rows; i++) {
        for (size_t j = 0; j < MAX_BIGNUM_WORDS / 2; j++) {
            BN_ULONG temp_a = test_values_a[i][j];
            test_values_a[i][j] = test_values_a[i][MAX_BIGNUM_WORDS - 1 - j];
            test_values_a[i][MAX_BIGNUM_WORDS - 1 - j] = temp_a;

            BN_ULONG temp_b = test_values_b[i][j];
            test_values_b[i][j] = test_values_b[i][MAX_BIGNUM_WORDS - 1 - j];
            test_values_b[i][MAX_BIGNUM_WORDS - 1 - j] = temp_b;
        }
    }
}

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
        {0xbfd25e8cd0364141, 0xbaaedce6af48a03b, 0xffffffffffffffe, 0xffffffffffffffff},
    };

    BN_ULONG test_values_n[][MAX_BIGNUM_WORDS] = {
        {0xcaa5c571ffccab5a, 0xad1c289591e564d3, 0x70116675aa53aa8a, 0x1b2db4c027cdbaba},
    };

    reverse_order(test_values_a, test_values_n, sizeof(test_values_a) / (sizeof(BN_ULONG) * MAX_BIGNUM_WORDS));

    // Number of tests defined by the number of elements in test_values_a/n arrays.
    int num_tests = sizeof(test_values_a) / sizeof(test_values_a[0]);

    for (int i = 0; i < num_tests; ++i) {
        printf("Test %d:\n", i);
        BIGNUM *a = BN_new();
        BIGNUM *n = BN_new();
        BIGNUM *mod_inverse = NULL;

        set_bignum_words(a, test_values_a[i], MAX_BIGNUM_WORDS);
        set_bignum_words(n, test_values_n[i], MAX_BIGNUM_WORDS);

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
    }

    BN_CTX_free(ctx);
    return 0;
}
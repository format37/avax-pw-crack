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
    printf("++ Starting BN_mod test ++\n");
    BN_CTX *ctx = BN_CTX_new();
    int mod;
    BIGNUM *remainder = BN_new();

    
    BN_ULONG test_values_a[][MAX_BIGNUM_WORDS] = {        
        {0xffffffffffffffff, 0xffffffffffffffe, 0xbaaedce6af48a03b, 0xbfd25e8cd0364141},
    };

    BN_ULONG test_values_n[][MAX_BIGNUM_WORDS] = {
        {0x1b2db4c027cdbaba, 0x70116675aa53aa8a, 0xad1c289591e564d3, 0xcaa5c571ffccab5a},
    };

    // 0 for positive, 1 for negative
    int sign_a[] = {0};
    int sign_n[] = {0};

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

        mod = BN_mod(remainder, a, n, ctx);

        printf("remainder: %s\n", BN_bn2hex(remainder));
        printf("mod: %d\n", mod);
        printf("\n");

        BN_free(a);
        BN_free(n);
    }

    BN_CTX_free(ctx);
    return 0;
}

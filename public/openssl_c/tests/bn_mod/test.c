#include <stdio.h>
#include <openssl/bn.h>
#include <openssl/err.h>

#define MAX_BIGNUM_WORDS 8

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

    
    /*BN_ULONG test_values_a[][MAX_BIGNUM_WORDS] = {        
        {0xffffffffffffffff, 0xffffffffffffffe, 0xbaaedce6af48a03b, 0xbfd25e8cd0364141},
        {0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xfffffffefffffc2f}
    };

    BN_ULONG test_values_n[][MAX_BIGNUM_WORDS] = {
        {0x1b2db4c027cdbaba, 0x70116675aa53aa8a, 0xad1c289591e564d3, 0xcaa5c571ffccab5a},
        {0x2d5971788066012b, 0xb9df77e2c7a41dba, 0x052181e3741e8338, 0x78e39ee6aa40ef8e},
    };
    // 0 for positive, 1 for negative
    int sign_a[] = {0,0};
    int sign_n[] = {0,1};*/

    BN_ULONG test_values_a[][MAX_BIGNUM_WORDS] = {
        {0xa9d76a4234a8ded, 0x7af964ec3f6f871b, 0xe09d7f67cc580732, 0x3b11b98c6222abbb, 0x0bdfd291448c33e6, 0xa46834fe88684cf0, 0x5106877163ee71eb, 0x5186b6de04720283},
        {0, 0, 0, 0x1, 0x2E09165B257A4C3E, 0x52C9F4FAA6322C65, 0x898D5D622CB3EEFF, 0x55DA7F062F1B85C0},
    };

    BN_ULONG test_values_n[][MAX_BIGNUM_WORDS] = {
        {0, 0, 0, 0, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xfffffffefffffc2f},
        {0, 0, 0, 0, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFE, 0xBAAEDCE6AF48A03B, 0xBFD25E8CD0364141},
    };
    // 0 for positive, 1 for negative
    int sign_a[] = {0,0};
    int sign_n[] = {0,0};

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
        if (sign_a[i]) BN_set_negative(a, 1);
        if (sign_n[i]) BN_set_negative(n, 1);

        print_bn("a", a);
        print_bn("n", n);

        //mod = BN_mod(remainder, a, n, ctx);
        mod = BN_nnmod(remainder, a, n, ctx);

        printf("remainder: %s\n", BN_bn2hex(remainder));
        printf("mod: %d\n", mod);
        printf("\n");

        BN_free(a);
        BN_free(n);
    }

    BN_CTX_free(ctx);
    return 0;
}

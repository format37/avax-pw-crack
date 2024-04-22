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

int BN_nnmod_debug(BIGNUM *r, const BIGNUM *m, const BIGNUM *d, BN_CTX *ctx)
{
    /*
     * like BN_mod, but returns non-negative remainder (i.e., 0 <= r < |d|
     * always holds)
     */
    printf("++ BN_nnmod_debug ++\n");
    printf(">> r: %s\n", BN_bn2hex(r));
    printf(">> m: %s\n", BN_bn2hex(m));
    printf(">> d: %s\n", BN_bn2hex(d));
    if (r == d) {
        printf("r == d\n");
        ERR_raise(ERR_LIB_BN, ERR_R_PASSED_INVALID_ARGUMENT);
        return 0;
    }

    if (!(BN_mod(r, m, d, ctx))) {
        printf("BN_mod failed\n");
        return 0;
    }
    // print r
    printf("[1] r: %s\n", BN_bn2hex(r));
    printf("[1] m: %s\n", BN_bn2hex(m));
    printf("[1] d: %s\n", BN_bn2hex(d));

    /* now   -|d| < r < 0,  so we have to set  r := r + |d| */
    if (BN_is_negative(r) == 0) {
        printf("r is not negative\n");
        return 1;
    }
    if (BN_is_negative(d)) {
        printf("d is negative\n");
        if (!BN_sub(r, r, d))
            printf("BN_sub failed\n");
            return 0;
    } else {
        printf("d is not negative\n");
        if (!BN_add(r, r, d))
            printf("BN_add failed\n");
            return 0;
    }
    printf("returning 1\n");
    return 1;
}

int main() {
    printf("++ Starting BN_mod test ++\n");
    BN_CTX *ctx = BN_CTX_new();
    int mod;
    BIGNUM *remainder = BN_new();

    
    BN_ULONG test_values_a[][MAX_BIGNUM_WORDS] = {
        {0x2d5971788066012b, 0xb9df77e2c7a41dba, 0x052181e3741e8338, 0x78e39ee6aa40ef8e}
        
    };

    BN_ULONG test_values_n[][MAX_BIGNUM_WORDS] = {
        {0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xfffffffefffffc2f}
    };

    // 0 for positive, 1 for negative
    int sign_a[] = {1};
    int sign_n[] = {0};

    // Number of tests defined by the number of elements in test_values_a/n arrays.
    int num_tests = sizeof(test_values_a) / sizeof(test_values_a[0]);

    //for (int test = 0; test < num_tests; ++test) {
    for (int i = 0; i < num_tests; ++i) {
        printf("Test %d:\n", i);
        BIGNUM *a = BN_new();
        BIGNUM *n = BN_new();

        set_bignum_words(a, test_values_a[i], MAX_BIGNUM_WORDS);
        set_bignum_words(n, test_values_n[i], MAX_BIGNUM_WORDS);

        // Set signs
        if (sign_a[i]) BN_set_negative(a, 1);
        if (sign_n[i]) BN_set_negative(n, 1);

        print_bn("a", a);
        print_bn("n", n);

        mod = BN_nnmod_debug(remainder, a, n, ctx);

        printf("remainder: %s\n", BN_bn2hex(remainder));
        printf("mod: %d\n", mod);
        printf("\n");

        BN_free(a);
        BN_free(n);
    }

    BN_CTX_free(ctx);
    return 0;
}
